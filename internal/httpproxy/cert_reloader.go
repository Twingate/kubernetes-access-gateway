// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/wait"
)

type certReloader struct {
	mu       sync.RWMutex
	certFile string
	keyFile  string
	watcher  *fsnotify.Watcher
	cert     *tls.Certificate
	logger   *zap.Logger

	cancel context.CancelFunc
}

func newCertReloader(certFile, keyFile string, logger *zap.Logger) *certReloader {
	return &certReloader{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
	}
}

func (cr *certReloader) run() {
	var ctx context.Context

	ctx, cr.cancel = context.WithCancel(context.Background())

	go wait.Until(func() {
		if err := cr.watch(ctx.Done()); err != nil {
			cr.logger.Error("failed to watch cert and key file, will retry later", zap.Error(err))
		}
	}, time.Minute, ctx.Done())
}

func (cr *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
	if err != nil {
		return err
	}

	cr.mu.Lock()
	defer cr.mu.Unlock()

	cr.cert = &cert

	return nil
}

func (cr *certReloader) watch(stopCh <-chan struct{}) error {
	var err error

	cr.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("error creating fsnotify watcher: %w", err)
	}
	defer cr.watcher.Close()

	if err := cr.watcher.Add(cr.certFile); err != nil {
		return fmt.Errorf("error adding watch for file %s: %w", cr.certFile, err)
	}

	if err := cr.watcher.Add(cr.keyFile); err != nil {
		return fmt.Errorf("error adding watch for file %s: %w", cr.keyFile, err)
	}

	if err := cr.load(); err != nil {
		return fmt.Errorf("error loading certificate: %w", err)
	}

	cr.logger.Info("Start watching cert and key files changes")

	for {
		select {
		case event := <-cr.watcher.Events:
			if err := cr.handleWatchEvent(event); err != nil {
				return err
			}
		case err := <-cr.watcher.Errors:
			cr.logger.Error("received error from watcher", zap.Error(err))

			return fmt.Errorf("received error from watcher: %w", err)

		case <-stopCh:
			return nil
		}
	}
}

func (cr *certReloader) handleWatchEvent(event fsnotify.Event) error {
	cr.logger.Info("Received watch event", zap.Any("event", event))

	if !event.Has(fsnotify.Remove) && !event.Has(fsnotify.Rename) {
		if err := cr.load(); err != nil {
			cr.logger.Error("failed to load cert or key file", zap.Error(err))
		}

		return nil
	}

	if err := cr.watcher.Remove(event.Name); err != nil {
		cr.logger.Info("failed to remove file watch, it may have been deleted", zap.Error(err))
	}

	if err := cr.watcher.Add(event.Name); err != nil {
		cr.logger.Error("error adding watch for file", zap.String("filename", event.Name), zap.Error(err))

		return err
	}

	return nil
}

func (cr *certReloader) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	return cr.cert, nil
}

func (cr *certReloader) stop() {
	cr.cancel()
	cr.logger.Info("Stopped watching cert and key files changes")
}
