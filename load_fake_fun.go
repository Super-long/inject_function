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
const relocationSection = ".rela.text"

type FakeImage struct {
	// symbolName is the name of the symbol to be replaced.
	symbolName string
	// content presents .text section which has been "manually relocation", the address of extern variables have been calculated manually
	content []byte
	// offset stores the table with variable name, and it's address in content.
	// the key presents extern variable name, ths value is the address/offset within the content.
	offset map[string]int
	// OriginFuncCode stores the raw func code like getTimeOfDay & ClockGetTime.
	OriginFuncCode []byte
	// OriginAddress stores the origin address of OriginFuncCode.
	OriginAddress uint64
	// fakeEntry stores the fake entry
	fakeEntry *Entry

}

func NewFakeImage(symbolName string, content []byte, offset map[string]int) *FakeImage {
	return &FakeImage{symbolName: symbolName, content: content, offset: offset}
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
	imageOffset := make(map[string]int)

	for _, r := range elfFile.Sections {

		if r.Type == elf.SHT_PROGBITS && r.Name == textSection {
			imageContent, err = r.Data()
			if err != nil {
				return nil, errors.Wrapf(err, "read text section data %s", path)
			}
			break
		}
	}

	for _, r := range elfFile.Sections {
		if r.Type == elf.SHT_RELA && r.Name == relocationSection {
			rela_section, err := r.Data()
			if err != nil {
				return nil, errors.Wrapf(err, "read rela section data %s", path)
			}
			rela_section_reader := bytes.NewReader(rela_section)

			var rela elf.Rela64
			for rela_section_reader.Len() > 0 {
				err := binary.Read(rela_section_reader, elfFile.ByteOrder, &rela)
				if err != nil {
					return nil, errors.Wrapf(err, "read rela section rela64 entry %s", path)
				}

				symNo := rela.Info >> 32
				if symNo == 0 || symNo > uint64(len(syms)) {
					continue
				}

				// The relocation of a X86 image is like:
				// Relocation section '.rela.text' at offset 0x288 contains 3 entries:
				// Offset          Info           Type           Sym. Value    Sym. Name + Addend
				// 000000000016  000900000002 R_X86_64_PC32     0000000000000000 CLOCK_IDS_MASK - 4
				// 00000000001f  000a00000002 R_X86_64_PC32     0000000000000008 TV_NSEC_DELTA - 4
				// 00000000002a  000b00000002 R_X86_64_PC32     0000000000000010 TV_SEC_DELTA - 4
				//
				// For example, we need to write the offset of `CLOCK_IDS_MASK` - 4 in 0x16 of the section
				// If we want to put the `CLOCK_IDS_MASK` at the end of the section, it will be
				// len(fakeImage.content) - 4 - 0x16

				sym := &syms[symNo-1]
				imageOffset[sym.Name] = len(imageContent)
				targetOffset := uint32(len(imageContent)) - uint32(rela.Off) + uint32(rela.Addend)
				elfFile.ByteOrder.PutUint32(imageContent[rela.Off:rela.Off+4], targetOffset)

				// TODO: support other length besides uint64 (which is 8 bytes)
				imageContent = append(imageContent, make([]byte, 8)...)
			}

			break
		}
	}
	return NewFakeImage(
		symbolName,
		imageContent,
		imageOffset,
	), nil
}
