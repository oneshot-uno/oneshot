package configuration

import (
	"errors"
	"os"
)

type SingletonOrSlice[T any] []T

func (sos *SingletonOrSlice[T]) UnmarshalYAML(unmarshal func(any) error) error {
	var singleton T
	if err := unmarshal(&singleton); err == nil {
		*sos = []T{singleton}
		return nil
	}

	var slice []T
	if err := unmarshal(&slice); err != nil {
		return err
	}
	*sos = slice
	return nil
}

type PathOrContent struct {
	Path    string `mapstructure:"path" yaml:"path"`
	Content string `mapstructure:"content" yaml:"content"`
}

func (poc *PathOrContent) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if poc == nil {
		*poc = PathOrContent{}
	}

	type poc_t PathOrContent
	if err := unmarshal((*poc_t)(poc)); err != nil {
		return err
	}

	if poc.Path != "" && poc.Content != "" {
		return errors.New("only one of path or content can be specified")
	}

	return nil
}

func (poc *PathOrContent) GetContent() ([]byte, error) {
	if poc.Content != "" {
		return []byte(poc.Content), nil
	}
	if poc.Path == "" {
		return nil, errors.New("no content or path specified")
	}

	return os.ReadFile(poc.Path)
}

type FileExport struct {
	Path string `mapstructure:"path" yaml:"path"`
	Mode string `mapstructure:"mode" yaml:"mode"`
}
