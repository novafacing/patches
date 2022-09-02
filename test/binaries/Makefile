CC=clang
CXX=clang++
CFLAGS=-O0 -g -ggdb

all: print_twice.bin cgc

print_twice.bin: print_twice.c
	$(CC) -o $@ $(CFLAGS) $^

cgc: AIS-Lite/AIS-Lite CGC_Board/CGC_Board CGC_Image_Parser/CGC_Image_Parser \
	CGC_Video_Format_Parser_and_Viewer/CGC_Video_Format_Parser_and_Viewer \
	Packet_Analyzer/Packet_Analyzer

AIS-Lite/AIS-Lite:
	cd AIS-Lite; mkdir -p build; cd build; \
		cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie' ..; \
		make; cp AIS-Lite ../AIS-Lite.bin; \
		find . -type f -name '*.so' -exec cp '{}' '..' \; ; \
		cd ..; rm -rf build;

CGC_Board/CGC_Board:
	cd CGC_Board; mkdir -p build; cd build; \
		cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie' ..; \
		make; cp CGC_Board ../CGC_Board.bin; \
		find . -type f -name '*.so' -exec cp '{}' '..' \; ; \
		cd ..; rm -rf build;

CGC_Image_Parser/CGC_Image_Parser:
	cd CGC_Image_Parser; mkdir -p build; cd build; \
		cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie' ..; \
		make; cp CGC_Image_Parser ../CGC_Image_Parser.bin; \
		find . -type f -name '*.so' -exec cp '{}' '..' \; ; \
		cd ..; rm -rf build;

CGC_Video_Format_Parser_and_Viewer/CGC_Video_Format_Parser_and_Viewer:
	cd CGC_Video_Format_Parser_and_Viewer; mkdir -p build; cd build; \
		cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie' ..; \
		make; cp CGC_Video_Format_Parser_and_Viewer ../CGC_Video_Format_Parser_and_Viewer.bin; \
		find . -type f -name '*.so' -exec cp '{}' '..' \; ; \
		cd ..; rm -rf build;

Packet_Analyzer/Packet_Analyzer:
	cd Packet_Analyzer; mkdir -p build; cd build; \
		cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie' ..; \
		make; cp Packet_Analyzer ../Packet_Analyzer.bin; \
		find . -type f -name '*.so' -exec cp '{}' '..' \; ; \
		cd ..; rm -rf build;

.PHONY: clean

clean:
	rm -f *.bin

