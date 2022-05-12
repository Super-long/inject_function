package main

import (
	"bytes"
	"debug/elf"
	"embed"
	"encoding/binary"

	"github.com/pkg/errors"
)

//go:embed fakefunc/*.o
var fakefunc embed.FS

const textSection = ".text"

type FakeImage struct {
	// symbolName is the name of the symbol to be replaced.
	symbolName string
	// content presents .text section which has been "manually relocation", the address of extern variables have been calculated manually
	content []byte
	// OriginFuncCode stores the raw func code like getTimeOfDay & ClockGetTime.
	OriginFuncCode []byte
	// OriginAddress stores the origin address of OriginFuncCode.
	OriginAddress uint64
	// fakeEntry stores the fake entry
	fakeEntry *Entry

}

func NewFakeImage(symbolName string, content []byte) *FakeImage {
	return &FakeImage{symbolName: symbolName, content: content}
}

// LoadFakeImageFromEmbedFs builds FakeImage from the embed filesystem. It parses the ELF file and extract the variables from the relocation section, reserves the space for them at the end of content, then calculates and saves offsets as "manually relocation"
func LoadFakeImageFromEmbedFs(filename string, symbolName string) (*FakeImage, error) {
	path := "fakefunc/" + filename
	object, err := fakefunc.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "read file from embedded fs %s", path)
	}

	elfFile, err := elf.NewFile(bytes.NewReader(object))
	if err != nil {
		return nil, errors.Wrapf(err, "parse elf file %s", path)
	}

	syms, err := elfFile.Symbols()
	if err != nil {
		return nil, errors.Wrapf(err, "get symbols %s", path)
	}

	var imageContent []byte

	for _, r := range elfFile.Sections {

		if r.Type == elf.SHT_PROGBITS && r.Name == textSection {
			imageContent, err = r.Data()
			if err != nil {
				return nil, errors.Wrapf(err, "read text section data %s", path)
			}
			break
		}
	}
	
	return NewFakeImage(
		symbolName,
		imageContent,
	), nil
}
