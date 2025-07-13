package output

import (
	"fmt"
	"os"
)

func LogError(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, Red+format+Reset+"\n", a...)
}
