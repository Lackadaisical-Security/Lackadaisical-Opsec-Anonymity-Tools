package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/h2non/filetype"
	"github.com/rwcarlsen/goexif/exif"
	"github.com/xor-gate/goexif2/mknote"
)

type MetadataCleaner struct {
	verbose bool
}

func NewMetadataCleaner(verbose bool) *MetadataCleaner {
	return &MetadataCleaner{verbose: verbose}
}

func (mc *MetadataCleaner) CleanFile(filePath string) error {
	// Detect file type
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	kind, _ := filetype.Match(buf)
	
	switch kind.Extension {
	case "jpg", "jpeg":
		return mc.cleanJPEG(filePath)
	case "png":
		return mc.cleanPNG(filePath)
	case "pdf":
		return mc.cleanPDF(filePath)
	case "docx", "xlsx", "pptx":
		return mc.cleanOffice(filePath)
	default:
		if mc.verbose {
			fmt.Printf("Unsupported file type: %s\n", kind.Extension)
		}
		return nil
	}
}

func (mc *MetadataCleaner) cleanJPEG(filePath string) error {
	// Read file
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Try to decode EXIF
	_, err = exif.Decode(f)
	if err != nil && err != exif.NotFoundError {
		return err
	}

	// Create temp file
	tempFile := filePath + ".tmp"
	out, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	defer out.Close()

	// Reset file pointer
	f.Seek(0, 0)

	// Copy image data without EXIF
	buf := make([]byte, 2)
	_, err = f.Read(buf)
	if err != nil {
		return err
	}

	// Write JPEG header
	out.Write([]byte{0xFF, 0xD8})

	// Skip EXIF data if present
	if buf[0] == 0xFF && buf[1] == 0xE1 {
		// Read EXIF segment size
		sizeBuf := make([]byte, 2)
		f.Read(sizeBuf)
		size := int(sizeBuf[0])<<8 + int(sizeBuf[1])
		
		// Skip EXIF data
		f.Seek(int64(size-2), 1)
	} else {
		// No EXIF, write back what we read
		out.Write(buf)
	}

	// Copy rest of file
	_, err = io.Copy(out, f)
	if err != nil {
		return err
	}

	// Replace original file
	os.Remove(filePath)
	os.Rename(tempFile, filePath)

	if mc.verbose {
		fmt.Printf("Cleaned JPEG: %s\n", filePath)
	}

	return nil
}

func (mc *MetadataCleaner) cleanPNG(filePath string) error {
	// PNG cleaning implementation
	// This is a simplified version - real implementation would parse PNG chunks
	
	input, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	output := make([]byte, 0, len(input))
	
	// PNG signature
	signature := []byte{137, 80, 78, 71, 13, 10, 26, 10}
	output = append(output, signature...)
	
	pos := 8
	for pos < len(input) {
		// Read chunk length
		if pos+4 > len(input) {
			break
		}
		length := int(input[pos])<<24 | int(input[pos+1])<<16 | int(input[pos+2])<<8 | int(input[pos+3])
		pos += 4
		
		// Read chunk type
		if pos+4 > len(input) {
			break
		}
		chunkType := string(input[pos : pos+4])
		
		// Skip metadata chunks
		if chunkType == "tEXt" || chunkType == "iTXt" || chunkType == "zTXt" || 
		   chunkType == "tIME" || chunkType == "pHYs" || chunkType == "gAMA" {
			pos += 4 + length + 4 // type + data + crc
			continue
		}
		
		// Copy chunk
		if pos+length+4 > len(input) {
			break
		}
		output = append(output, input[pos-4:pos+4+length+4]...)
		pos += 4 + length + 4
	}
	
	// Write cleaned file
	err = os.WriteFile(filePath, output, 0644)
	if err != nil {
		return err
	}
	
	if mc.verbose {
		fmt.Printf("Cleaned PNG: %s\n", filePath)
	}
	
	return nil
}

func (mc *MetadataCleaner) cleanPDF(filePath string) error {
	// PDF metadata cleaning - simplified version
	// Real implementation would use a PDF library
	
	if mc.verbose {
		fmt.Printf("PDF cleaning not yet implemented: %s\n", filePath)
	}
	return nil
}

func (mc *MetadataCleaner) cleanOffice(filePath string) error {
	// Office document cleaning - simplified version
	// Real implementation would parse Office Open XML format
	
	if mc.verbose {
		fmt.Printf("Office document cleaning not yet implemented: %s\n", filePath)
	}
	return nil
}

func (mc *MetadataCleaner) CleanDirectory(dirPath string, recursive bool) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			if !recursive && path != dirPath {
				return filepath.SkipDir
			}
			return nil
		}
		
		return mc.CleanFile(path)
	})
}

func main() {
	var (
		recursive = flag.Bool("r", false, "Process directories recursively")
		verbose   = flag.Bool("v", false, "Verbose output")
	)
	
	flag.Parse()
	
	if flag.NArg() == 0 {
		fmt.Println("Usage: metadata_cleaner [-r] [-v] <file_or_directory>...")
		os.Exit(1)
	}
	
	cleaner := NewMetadataCleaner(*verbose)
	
	for _, arg := range flag.Args() {
		info, err := os.Stat(arg)
		if err != nil {
			log.Printf("Error accessing %s: %v\n", arg, err)
			continue
		}
		
		if info.IsDir() {
			err = cleaner.CleanDirectory(arg, *recursive)
		} else {
			err = cleaner.CleanFile(arg)
		}
		
		if err != nil {
			log.Printf("Error processing %s: %v\n", arg, err)
		}
	}
}
