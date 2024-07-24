// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"os"
	"strings"
)

func write(str string) {
	os.Stdout.WriteString(str)
}

func parseService(line string) string {
	return strings.Split(line, " ")[1]
}

func parsePushRefs(line string) (string, string, bool) {
	parts := strings.Split(line, " ")
	parts = strings.Split(parts[1], ":")
	src := parts[0]
	dst := parts[1]
	force := false
	if strings.HasPrefix(src, "+") {
		strings.TrimPrefix(src, "+")
		force = true
	}
	return src, dst, force
}

func transport() {

	stdinScanner := bufio.NewScanner(os.Stdin)

	for stdinScanner.Scan() {
		line := stdinScanner.Text()

		switch {
		case line == "capabilities":
			write("stateless-connect\npush\n\n")

		case strings.HasPrefix(line, "stateless-connect"):
			service := parseService(line)

			// TODO: We only support stateless-connect fetch
			// write "fallback", if git wants to do a stateless-connect  push

			// Setup ssh command with pipes

			// Do initial request, and parse response (refs)

			// Indicate connection established successfully
			write("\n")

			// ...

		case line == "list for-push":

			// ...

		case strings.HasPrefix(line, "push"):

			// Continue scanning stdin, there might be more pushes
			// coming along
			src, dst, force := parsePushRefs(line)

		}

	}
}
