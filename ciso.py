#!/usr/bin/python3

import os
import struct
import sys
import zlib

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_WBITS = -15 # Maximum window size, suppress gzip header check.
CISO_PLAIN_BLOCK = 0x80000000

#assert(struct.calcsize(CISO_HEADER_FMT) == CISO_HEADER_SIZE)

def get_terminal_size(fd=sys.stdout.fileno()):
	try:
		import fcntl, termios
		hw = struct.unpack("hh", fcntl.ioctl(
			fd, termios.TIOCGWINSZ, '1234'))
	except:
		try:
			hw = (os.environ['LINES'], os.environ['COLUMNS'])
		except:
			hw = (25, 80)
	return hw

(console_height, console_width) = get_terminal_size()

def seek_and_read(f, pos, size):
	f.seek(pos, os.SEEK_SET)
	return f.read(size)

def parse_header_info(header_data):
	(magic, header_size, total_bytes, block_size,
			ver, align) = header_data
	if magic == CISO_MAGIC:
		ciso = {
			'magic': magic,
			'magic_str': ''.join(
				[chr(magic >> i & 0xFF) for i in (0,8,16,24)]),
			'header_size': header_size,
			'total_bytes': total_bytes,
			'block_size': block_size,
			'ver': ver,
			'align': align,
			'total_blocks': int(total_bytes / block_size),
			}
		ciso['index_size'] = (ciso['total_blocks'] + 1) * 4
	else:
		raise Exception("Not a CISO file.")
	return ciso

def update_progress(progress):
	barLength = console_width - len("Progress: 100% []") - 1
	block = int(round(barLength*progress)) + 1
	text = "\rProgress: [{blocks}] {percent:.0f}%".format(
			blocks="#" * block + "-" * (barLength - block),
			percent=progress * 100)
	sys.stdout.write(text)
	sys.stdout.flush()

def decompress_cso(infile, outfile):
	with open(outfile, 'wb') as fout:
		with open(infile, 'rb') as fin:
			data = seek_and_read(fin, 0, CISO_HEADER_SIZE)
			header_data = struct.unpack(CISO_HEADER_FMT, data)
			ciso = parse_header_info(header_data)

			# Print some info before we start
			print("Decompressing '{}' to '{}'".format(
				infile, outfile))
			for k, v in ciso.items():
				print("{}: {}".format(k, v))

			# Get the block index
			block_index = [struct.unpack("<I", fin.read(4))[0]
					for i in
					range(0, ciso['total_blocks'] + 1)]

			percent_period = ciso['total_blocks'] / 100
			percent_cnt = 0

			for block in range(0, ciso['total_blocks']):
				#print("block={}".format(block))
				index = block_index[block]
				plain = index & 0x80000000
				index &= 0x7FFFFFFF
				read_pos = index << (ciso['align'])
				#print("index={}, plain={}, read_pos={}".format(
				#	index, plain, read_pos))

				if plain:
					read_size = ciso['block_size']
				else:
					index2 = block_index[block + 1] & 0x7FFFFFFF
					read_size = (index2 - index) << (ciso['align'])

				raw_data = seek_and_read(fin, read_pos, read_size)
				raw_data_size = len(raw_data)
				if raw_data_size != read_size:
					#print("read_size={}".format(read_size))
					#print("block={}: read error".format(block))
					sys.exit(1)

				if plain:
					decompressed_data = raw_data
				else:
					decompressed_data = zlib.decompress(raw_data, CISO_WBITS)

				# Write decompressed data to outfile
				fout.write(decompressed_data)

				# Progress bar
				percent = int(round((block / (ciso['total_blocks'] + 1)) * 100))
				if percent > percent_cnt:
					update_progress((block / (ciso['total_blocks'] + 1)))
					percent_cnt = percent
		# close infile
	# close outfile
	return True

def check_file_size(f):
	f.seek(0, os.SEEK_END)
	file_size = f.tell()
	ciso = {
			'magic': CISO_MAGIC,
			'ver': 1,
			'block_size': CISO_BLOCK_SIZE,
			'total_bytes': file_size,
			'total_blocks': int(file_size / CISO_BLOCK_SIZE),
			'align': 0,
			}
	f.seek(0, os.SEEK_SET)
	return ciso

def write_cso_header(f, ciso):
	f.write(struct.pack(CISO_HEADER_FMT,
		ciso['magic'],
		CISO_HEADER_SIZE,
		ciso['total_bytes'],
		ciso['block_size'],
		ciso['ver'],
		ciso['align']
		))

def write_block_index(f, block_index):
	for index, block in enumerate(block_index):
		try:
			f.write(struct.pack('<I', block))
		except Exception as e:
			print("Writing block={} with data={} failed.".format(
				index, block))
			print(e)
			sys.exit(1)

def compress_iso(infile, outfile, compression_level):
	with open(outfile, 'wb') as fout:
		with open(infile, 'rb') as fin:
			print("Compressing '{}' to '{}'".format(
				infile, outfile))

			ciso = check_file_size(fin)
			for k, v in ciso.items():
				print("{}: {}".format(k, v))
			print("compress level: {}".format(compression_level))

			write_cso_header(fout, ciso)
			block_index = [0x00] * (ciso['total_blocks'] + 1)

			# Write the dummy block index for now.
			write_block_index(fout, block_index)

			write_pos = fout.tell()
			align_b = 1 << ciso['align']
			align_m = align_b - 1

			# Alignment buffer is unsigned char.
			alignment_buffer = struct.pack('<B', 0x00) * 64

			# Progress counters
			percent_period = ciso['total_blocks'] / 100
			percent_cnt = 0

			for block in range(0, ciso['total_blocks']):
				# Write alignment
				align = int(write_pos & align_m)
				if align:
					align = align_b - align
					size = fout.write(alignment_buffer[:align])
					write_pos += align
				
				# Mark offset index
				block_index[block] = write_pos >> ciso['align']

				# Read raw data
				raw_data = fin.read(ciso['block_size'])
				raw_data_size = len(raw_data)

				# Compress block
				# Compressed data will have the gzip header on it, we strip that.
				compressed_data = zlib.compress(raw_data, compression_level)[2:]
				compressed_size = len(compressed_data)

				if compressed_size >= raw_data_size:
					writable_data = raw_data
					# Plain block marker
					block_index[block] |= 0x80000000
					# Next index
					write_pos += raw_data_size
				else:
					writable_data = compressed_data
					# Next index
					write_pos += compressed_size

				# Write data
				fout.write(writable_data)

				# Progress bar
				percent = int(round((block / (ciso['total_blocks'] + 1)) * 100))
				if percent > percent_cnt:
					update_progress((block / (ciso['total_blocks'] + 1)))
					percent_cnt = percent

			# end for block
			# last position (total size)
			block_index[block] = write_pos >> ciso['align']

			# write header and index block
			print("Writing block index")
			fout.seek(CISO_HEADER_SIZE, os.SEEK_SET)
			write_block_index(fout, block_index)
		# end open(infile)

def main(argv):
	compression_level = int(argv[1])
	infile = argv[2]
	outfile = argv[3]
	if compression_level:
		compress_iso(infile, outfile, compression_level)
	else:
		decompress_cso(infile, outfile)

if __name__ == '__main__':
	sys.exit(main(sys.argv))
