// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/gittuf/gittuf/internal/gitinterface"
	"github.com/go-git/go-git/v5/plumbing"
)

var (
	ErrCloningRepository = errors.New("unable to clone repository")
	ErrDirExists         = errors.New("directory exists")
)

// Clone wraps a typical git clone invocation, fetching gittuf refs in addition
// to the standard refs. It performs a verification of the RSL against the
// specified HEAD after cloning the repository.
// TODO: resolve how root keys are trusted / bootstrapped.
func Clone(ctx context.Context, remoteURL, dir, initialBranch string) (*Repository, error) {
	slog.Debug(fmt.Sprintf("Cloning from '%s'...", remoteURL))

	if dir == "" {
		// FIXME: my understanding is backslashes are not used in URLs but I haven't dived into the RFCs to check yet
		modifiedURL := strings.ReplaceAll(remoteURL, "\\", "/")
		modifiedURL = strings.TrimRight(strings.TrimSpace(modifiedURL), "/") // Trim spaces and trailing slashes if any

		split := strings.Split(modifiedURL, "/")
		dir = strings.TrimSuffix(split[len(split)-1], ".git")
	}

	slog.Debug("Checking if local directory exists for repository...")
	_, err := os.Stat(dir)
	if err == nil {
		return nil, errors.Join(ErrCloningRepository, ErrDirExists)
	} else if !os.IsNotExist(err) {
		return nil, errors.Join(ErrCloningRepository, err)
	}

	if err := os.Mkdir(dir, 0755); err != nil {
		return nil, errors.Join(ErrCloningRepository, err)
	}

	refs := []string{"refs/gittuf/*"}

	slog.Debug("Cloning repository...")
	r, err := gitinterface.CloneAndFetch(ctx, remoteURL, dir, initialBranch, refs)
	if err != nil {
		if e := os.RemoveAll(dir); e != nil {
			return nil, errors.Join(ErrCloningRepository, err, e)
		}
		return nil, errors.Join(ErrCloningRepository, err)
	}
	head, err := r.Reference(plumbing.HEAD, false)
	if err != nil {
		return nil, errors.Join(ErrCloningRepository, err)
	}

	repository := &Repository{r: r}

	slog.Debug("Verifying HEAD...")
	return repository, repository.VerifyRef(ctx, head.Target().String(), false)
}
