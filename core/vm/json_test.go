package vm

import (
	"bytes"
	"sort"

	//"bytes"
	"encoding/json"
	"fmt"
	//"sort"
	"testing"
)

type OrderedMap struct {
	Order []string
	Map   map[string]string
}

func (om *OrderedMap) UnmarshalJSON(b []byte) error {
	json.Unmarshal(b, &om.Map)

	index := make(map[string]int)
	for key := range om.Map {
		om.Order = append(om.Order, key)
		esc, _ := json.Marshal(key) //Escape the key
		index[key] = bytes.Index(b, esc)
	}

	sort.Slice(om.Order, func(i, j int) bool { return index[om.Order[i]] < index[om.Order[j]] })
	return nil
}

func (om OrderedMap) MarshalJSON() ([]byte, error) {
	var b []byte
	buf := bytes.NewBuffer(b)
	buf.WriteRune('{')
	l := len(om.Order)
	for i, key := range om.Order {
		km, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buf.Write(km)
		buf.WriteRune(':')
		vm, err := json.Marshal(om.Map[key])
		if err != nil {
			return nil, err
		}
		buf.Write(vm)
		if i != l-1 {
			buf.WriteRune(',')
		}
		fmt.Println(buf.String())
	}
	buf.WriteRune('}')
	fmt.Println(buf.String())
	return buf.Bytes(), nil
}

//func main() {
//	obj := `{"key3": "value3", "key2": "value2", "key1": "value1"}`
//	var o OrderedMap
//	json.Unmarshal([]byte(obj), &o)
//	r, err := json.Marshal(o)
//	fmt.Println(string(r), err)
//}

func TestJsonSort(t *testing.T) {

	obj := `{"key3": "value3", "key2": "value2", "key1": "value1"}`
	var o OrderedMap
	json.Unmarshal([]byte(obj), &o)
	r, err := json.Marshal(o)
	fmt.Println(string(r), err)

}

func TestJsonSortNormal(t *testing.T) {

	obj := `{"key3":"value3","key2":"value2","key1":"value1"}`
	var o map[string]interface{}
	json.Unmarshal([]byte(obj), &o)
	fmt.Println(o)
	r, _ := json.Marshal(o)
	fmt.Println(string(r))

}
