/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package transport

import (
	"bytes"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const caRotationWorkItemKey = "ca-rotation"

// CARotationRefreshDuration is exposed so that integration tests can crank up the reload speed.
var CARotationRefreshDuration = 5 * time.Minute

// atomicTransportHolder holds a transport that can be atomically updated
// when CA files change, enabling graceful CA rotation without cache complexity
type atomicTransportHolder struct {
	transport    atomic.Pointer[http.Transport]
	caFile       string
	config       *Config
	logger       klog.Logger
	
	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.RateLimitingInterface
}

// RoundTrip implements http.RoundTripper interface
func (h *atomicTransportHolder) RoundTrip(req *http.Request) (*http.Response, error) {
	return h.transport.Load().RoundTrip(req)
}

// newAtomicTransportHolder creates a new holder for CA file reloading scenarios
func newAtomicTransportHolder(config *Config, initialTransport *http.Transport) *atomicTransportHolder {
	holder := &atomicTransportHolder{
		caFile: config.TLS.CAFile,
		config: config,
		logger: klog.Background().WithName("ca-transport-holder"),
		queue: workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(),
			"CARotation",
		),
	}
	holder.transport.Store(initialTransport)
	
	return holder
}

// run starts the controller and blocks until stopCh is closed.
func (h *atomicTransportHolder) run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrashWithLogger(h.logger)
	defer h.queue.ShutDown()

	h.logger.V(3).Info("Starting CA rotation controller")
	defer h.logger.V(3).Info("Shutting down CA rotation controller")

	go wait.Until(h.runWorker, time.Second, stopCh)

	go wait.PollImmediateUntil(CARotationRefreshDuration, func() (bool, error) {
		h.queue.Add(caRotationWorkItemKey)
		return false, nil
	}, stopCh)

	<-stopCh
}

func (h *atomicTransportHolder) runWorker() {
	for h.processNextWorkItem() {
	}
}

func (h *atomicTransportHolder) processNextWorkItem() bool {
	obj, quit := h.queue.Get()
	if quit {
		return false
	}
	defer h.queue.Done(obj)

	err := h.checkCAFileAndRotate()
	if err == nil {
		h.queue.Forget(obj)
		return true
	}

	utilruntime.HandleErrorWithLogger(h.logger, err, "CA file rotation check failed", "key", obj)
	h.queue.AddRateLimited(obj)

	return true
}

// checkCAFileAndRotate checks if the CA file has changed and rotates the transport if needed
func (h *atomicTransportHolder) checkCAFileAndRotate() error {
	h.logger.V(2).Info("Checking CA file content", "caFile", h.caFile)
	
	// Get current CA data from config
	currentCAData := h.config.TLS.CAData
	
	// Load new CA data from file
	newCAData, err := os.ReadFile(h.caFile)
	if err != nil {
		h.logger.Error(err, "Failed to load CA data from file", "caFile", h.caFile)
		return err
	}

    if len(currentCAData) == 0 {
        h.logger.Info("No CA data in config, using CA data from file", "caFile", h.caFile)
		return nil
    }

	if bytes.Equal(currentCAData, newCAData) {
		h.logger.V(2).Info("CA content unchanged, skipping transport rotation", "caFile", h.caFile)
		return nil
	}

	h.logger.V(2).Info("CA content changed, updating transport", "caFile", h.caFile)
	
	// Load new CA pool from updated config
	newCAs, err := rootCertPool(newCAData)
	if err != nil {
		h.logger.Error(err, "Failed to load CA pool from CA file", "caFile", h.caFile)
		return err
	}
	
	// Clone the current transport and update its RootCAs
	newTransport := h.transport.Load().Clone()
	newTransport.TLSClientConfig.RootCAs = newCAs
	oldTransport := h.transport.Swap(newTransport)
	if oldTransport != nil {
		// Close idle connections on the old transport to encourage migration
		oldTransport.CloseIdleConnections()
	}
	
	h.logger.V(1).Info("Transport updated for CA rotation", "caFile", h.caFile)

	return nil
}

// stop stops the CA file monitoring
func (h *atomicTransportHolder) stop() {
	h.queue.ShutDown()
} 