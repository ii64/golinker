package link

import (
	"fmt"

	"github.com/ii64/golinker/conf"
	"github.com/ii64/golinker/lib/link/elf"
	"github.com/ii64/golinker/lib/obj"
)

type LinkState struct {
	elf *elf.LinkState
}

func Link(cfg *conf.Config, obj *obj.Object) (state *LinkState, err error) {
	// todo: check magic of object to determine obj type.
	switch {
	case obj.Elf != nil:
		state = &LinkState{}
		state.elf, err = elf.New(cfg, obj.Elf)
		if err != nil {
			return
		}
		err = state.elf.Generate()
		return
	default:
		err = fmt.Errorf("unknown object %+#v", obj)
	}
	return
}
