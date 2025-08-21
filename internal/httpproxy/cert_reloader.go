// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"crypto/tls"
	"sync"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type certReloader struct {
	mu       sync.RWMutex
	certFile string
	keyFile  string
	watching chan bool
	cert     *tls.Certificate
	logger   *zap.SugaredLogger
}

func newCertReloader(certFile, keyFile string, logger *zap.SugaredLogger) *certReloader {
	return &certReloader{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
		watching: make(chan bool),
	}
}

func (cr *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
	if err != nil {
		return err
	}

	cr.mu.Lock()
	defer cr.mu.Unlock()

	cr.cert = &cert
	cr.logger.Info("loaded cert and key files")

	return nil
}

func (cr *certReloader) watch() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		cr.logger.Fatal("failed to create watcher", zap.Error(err))
	}

	if err := watcher.Add(cr.certFile); err != nil {
		cr.logger.Fatal("failed to watch cert file: ", cr.certFile, zap.Error(err))
	}

	if err := watcher.Add(cr.keyFile); err != nil {
		cr.logger.Fatal("failed to watch key file: ", cr.keyFile, zap.Error(err))
	}

	cr.logger.Info("Start watching cert and key files changes")

	if err := cr.load(); err != nil {
		cr.logger.Error("failed to load cert or key file", zap.Error(err))
	}

	go func() {
		for {
			select {
			case <-cr.watching:
				_ = watcher.Close()
				cr.logger.Info("Stopped watching cert and key files changes")

				return
			case event := <-watcher.Events:
				cr.logger.Info("Received watch event: ", event)

				if err := cr.load(); err != nil {
					cr.logger.Error("failed to load cert or key file", zap.Error(err))
				}
			case err := <-watcher.Errors:
				cr.logger.Error("received error from watcher", zap.Error(err))
			}
		}
	}()
}

func (cr *certReloader) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	return cr.cert, nil
}

func (cr *certReloader) stop() {
	cr.watching <- false
}
