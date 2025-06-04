package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	// 
	var subsOnly bool
	var excludeFlag string
	var listSources bool

	flag.BoolVar(&subsOnly, "subs-only", false, "Only include subdomains of search domain")
	flag.StringVar(&excludeFlag, "exclude", "", "Comma-separated list of sources to exclude (e.g. crtsh,virustotal)")
	flag.BoolVar(&listSources, "list-sources", false, "List all available sources and exit")
	flag.Parse()
	

	/*sources := []fetchFn{
		fetchCertSpotter,
		fetchHackerTarget,
		fetchThreatCrowd,
		fetchCrtSh,
		fetchFacebook,
		//fetchWayback, // A little too slow :(
		fetchVirusTotal,
		fetchFindSubDomains,
		fetchUrlscan,
		fetchBufferOverrun,
	}*/

	sourceMap := map[string]fetchFn{
		"certspotter":    fetchCertSpotter,
		"hackertarget":   fetchHackerTarget,
		"threatcrowd":    fetchThreatCrowd,
		"crtsh":          fetchCrtSh,
		"facebook":       fetchFacebook,
		"virustotal":     fetchVirusTotal,
		"findsubdomains": fetchFindSubDomains,
		"urlscan":        fetchUrlscan,
		"bufferoverrun":  fetchBufferOverrun,
	}

	if listSources {
		fmt.Println("Available sources:")
		for name := range sourceMap {
			fmt.Println("-", name)
		}
		return
	}

	// exclude the sources
	exclude := map[string]bool{}
	if excludeFlag != "" {
		for _, name := range strings.Split(excludeFlag, ",") {
			exclude[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}

	sources := []fetchFn{}
	for name, fn := range sourceMap {
		if !exclude[name] {
			sources = append(sources, fn)
		}
	}

	// debug
	if len(sources) == 0 {
		fmt.Println("[INFO] No sources selected after applying -exclude flag.")
		os.Exit(0)
	}

	var domains io.Reader
	stat, _ := os.Stdin.Stat()
	//domains = os.Stdin
	
	// stdin = 0
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		domains = os.Stdin
	} else if flag.NArg() > 0 {
		domains = strings.NewReader(flag.Arg(0))
	} else {
		fmt.Println("Usage: echo domain | assetfinder [flags]  OR  assetfinder [flags] domain")
		fmt.Println()
		fmt.Println("Flags:")
		fmt.Println("  -subs-only      Only include subdomains of search domain")
		fmt.Println("  -exclude        Comma-separated list of sources to exclude (e.g. crtsh,virustotal)")
		fmt.Println("  -list-sources   List all available sources and exit")
		os.Exit(1)
	}

	//

	out := make(chan string)
	var wg sync.WaitGroup

	sc := bufio.NewScanner(domains)
	rl := newRateLimiter(time.Second)

	for sc.Scan() {
		domain := strings.ToLower(sc.Text())

		// call each of the source workers in a goroutine
		for _, source := range sources {
			wg.Add(1)
			fn := source

			go func() {
				defer wg.Done()

				rl.Block(fmt.Sprintf("%#v", fn))
				names, err := fn(domain)

				if err != nil {
					//fmt.Fprintf(os.Stderr, "err: %s\n", err)
					return
				}

				for _, n := range names {
					n = cleanDomain(n)
					if subsOnly && !strings.HasSuffix(n, domain) {
						continue
					}
					out <- n
				}
			}()
		}
	}

	// close the output channel when all the workers are done
	go func() {
		wg.Wait()
		close(out)
	}()

	// track what we've already printed to avoid duplicates
	printed := make(map[string]bool)

	for n := range out {
		if _, ok := printed[n]; ok {
			continue
		}
		printed[n] = true

		fmt.Println(n)
	}
}

type fetchFn func(string) ([]string, error)

func httpGet(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}

	raw, err := ioutil.ReadAll(res.Body)

	res.Body.Close()
	if err != nil {
		return []byte{}, err
	}

	return raw, nil
}

func cleanDomain(d string) string {
	d = strings.ToLower(d)

	// no idea what this is, but we can't clean it ¯\_(ツ)_/¯
	if len(d) < 2 {
		return d
	}

	if d[0] == '*' || d[0] == '%' {
		d = d[1:]
	}

	if d[0] == '.' {
		d = d[1:]
	}

	return d

}

func fetchJSON(url string, wrapper interface{}) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)

	return dec.Decode(wrapper)
}
