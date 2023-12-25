package config

import (
	"fmt"
	"regexp"
	"strings"
)

type Tag struct {
	Key    string
	Values []string
}

func Parse(input string) (string, []string, error) {
	match, err := regexp.MatchString(`\w+:(\w+)(,\w+)*`, input)
	if err != nil {
		return "", []string{}, fmt.Errorf("cannot validate the tag %s with error: %s", input, err.Error())
	}
	if !match {
		return "", []string{}, fmt.Errorf("tag %s has wrong format, this must match this format: key:value1[,value2,...]", input)
	}
	out := strings.Split(input, ":")
	return out[0], out[1:], nil
}

func (t *Tag) String() string {
	return fmt.Sprintf("tag:%s-%s", t.Key, t.Values)
}

func (t *Tag) Set(tagString string) error {
	if key, values, err := Parse(tagString); err != nil {
		return err
	} else {
		t.Key = key
		t.Values = values
	}

	return nil
}

func (t *Tag) IsZero() bool {
	return t.Key == "" && len(t.Values) == 0
}
