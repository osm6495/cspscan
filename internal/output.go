package internal

import "fmt"

func ToConsole(result Result, verbose bool) {
	if result.Error != nil {
		panic(fmt.Errorf("error with result:\nSource URL: %s\nSecondary URL: %s\nError: %v", result.PrimaryURL, result.SecondaryURL, result.Error.Error()))
	}
	
	if result.Vulnerable {
		fmt.Printf("Found possibly vulnerable url: Source URL - %s, Vulnerable URL - %s\n", result.PrimaryURL, result.SecondaryURL)
	}

	if verbose {
		fmt.Printf("Scanned URL: %s\n", result.SecondaryURL)
	}
}