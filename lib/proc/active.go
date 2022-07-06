package proc

import "sync"

var activeProcess = processList{}
var _activeProcessMu sync.Mutex

type processList map[*Process]struct{}

func (pl *processList) Add(p *Process) {
	_activeProcessMu.Lock()
	defer _activeProcessMu.Unlock()
	activeProcess[p] = struct{}{}
}

func CheckActiveProcess() {
	for proc, _ := range activeProcess {
		_ = proc
	}
}
