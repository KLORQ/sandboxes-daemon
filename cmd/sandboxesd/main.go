package main

import (
	"fmt"
	"os"

	"github.com/KLORQ/sandboxes-daemon/internal/version"
)

func main() {
	_, _ = fmt.Fprintf(os.Stdout, "sandboxesd %s\n", version.Version)
}
