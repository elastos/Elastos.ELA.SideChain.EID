package did

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestJSONMarshal(t *testing.T) {
	str := "abc\u0026def"
	data, _ := JSONMarshal(str)

	data2, _ := json.Marshal(str)

	fmt.Println(string(data))
	fmt.Println(string(data2))
}
