#!/usr/bin/python
import subprocess

import sys
import os
sys.path.append((os.path.abspath("..")))

from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_sh_flags
from elftools.elf.constants import SH_FLAGS
from capstone import *


jump_ins = {'jo', 'jno', 'js', 'jns', 'je', 'jne', 'jz', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz'}


class Node:
    def __init__(self, curr, tnext, fnext, first= None):
        self.curr = curr
        self.tnext = tnext
        self.fnext = fnext
        self.first = first
    

    def __repr__(self):
        if self.first== True:
            return "1st Node(0x%x)" % (self.curr) 
        elif self.fnext:
            return "Node(0x%x, %s, 0x%x)" % (self.curr, self.tnext, self.fnext)
        else:
            return "Node(0x%x, %s)" % (self.curr, self.tnext)


class Flow_Graph_Creator():
	def __init__(self, f, to_look=None):
		self.flows = {}
		self.funcAdd_map = {}
		self.sym_map = {}
		self.plt_start, self.plt_end, self.plti = None, None, None
		self.f = f
		self.plts = []
		self.align = None
		if to_look:
			self.to_look = set(to_look)
		else:
			self.to_look = None

	def parse_symbols(self, s):
		offset = s['sh_offset']
		ibytes = s['sh_size']
		addr   = s['sh_addr']
		syms = []

		for i in range(s.num_symbols()):
			sym = s.get_symbol(i)
			if sym.entry['st_info']['type'] == 'STT_FUNC' and sym.entry['st_info']['bind'] == 'STB_GLOBAL':
				if sym.entry['st_size'] > 0:
					syms.append((sym.name, sym.entry))
					self.funcAdd_map[sym.entry['st_value']] = (sym.entry['st_value']+(sym.entry['st_size']))
					self.sym_map['0x%x' % (sym.entry['st_value'])] = (sym.name, sym.entry['st_size'])
				if sym.entry['st_size'] == 0 and self.plti < self.plt_end:
					self.sym_map['0x%x' % self.plti] = (sym.name, sym.entry['st_size'])
					self.plts.append(sym.name)
					self.plti += 16
			elif self.to_look:
				syms.append((sym.name, sym.entry))
				self.sym_map['0x%x' % (sym.entry['st_value'])] = (sym.name, sym.entry['st_size'])
				self.funcAdd_map[sym.entry['st_value']] = (sym.entry['st_value']+(sym.entry['st_size']))
		# print('funcAdd_map = ', funcAdd_map)
		# print("sym_map = ", sym_map)
		for sym in syms:
			if not self.to_look or sym[0] in self.to_look:
				print('name:%s type:%s bind:%s from:0x%x to:0x%x' % (sym[0], sym[1]['st_info']['type'], sym[1]['st_info']['bind'], sym[1]['st_value'], (sym[1]['st_value']+sym[1]['st_size'])))
				self.disas_section(offset=sym[1]['st_value'], size=sym[1]['st_size'], stack=set(), count=0)
		return syms


	def disas_section(self, offset, size=None, count=0, stack=set()):
		if size:
			ibytes = size
		else:
			ibytes = 8192
	
		if offset in stack:
			print '|' + '   '*count+ '   LOOPED'
			return
		stack.add(offset)
	
		addr = offset
		nodes = []
		self.f.seek(offset-self.align)
		pbytes = 0 # Processed bytes

		while pbytes < ibytes:
			rbytes = ibytes - pbytes
			if rbytes > 8192:
				rbytes = 819
			data = self.f.read(rbytes)

			dbytes = 0
			prev = None
			first= None

			for i in self.md.disasm(data, addr + pbytes):
				if prev:
					prev.fnext = i.address
					nodes.append(prev)
					prev = None
				if i.mnemonic in {'call', 'callq'}:
					nodes.append(Node(curr=i.address, tnext=i.op_str, fnext=None))
					print '|' + '   '*count+ '\- %s %s' % (i.mnemonic, i.op_str),
					if i.op_str.startswith('0x'):
						off = int(i.op_str, 16)

						try:
							o = self.sym_map[i.op_str]
						except:
							o = ('', None)

						if self.plt_start <= off < self.plt_end:
							print('   <%s@plt>' % o[0])
						else:
							print('   <%s>' % o[0])
							self.disas_section(offset=off, size=o[1], count=count+1, stack=stack)
					else:
						print '' 
				elif i.mnemonic in {'ret', 'retq'}:					#end of fuction
					ibytes -= (10*ibytes)							#to get out of while loop
					break											#to get out of for loop
				elif i.mnemonic.startswith('j'):
					print '|'+'   '*count+ '\- %s %s' % (i.mnemonic, i.op_str),
					if i.op_str.startswith('0x'):
						off = int(i.op_str,16)
						try:
							o = self.sym_map[i.op_str]
						except:
							o = ('', offset+ibytes)
						if off >= offset and  off <= o[1]:
							# print('   '*count+ 'offset:%x offset+size:%x' % (offset, funcAdd_map[offset]))
							print '   inside same function'
						else:
							print '   to other function'
							self.disas_section(offset=off, count=count+1)
					else:
						print ''
						if i.mnemonic.startswith('jmp'):
							# process ahead from address of operand
							return
					prev = Node(curr=i.address, tnext=i.op_str, fnext=None)

				dbytes += i.size

			pbytes += dbytes

			if dbytes < rbytes:
				self.f.seek(offset + pbytes - self.align)
			if not size:
				ibytes += 8192				#if case there is more than one page
		return nodes

	def parse_elf(self):
		self.f = open(self.f, 'rb') #read binary form commad line

		elff = ELFFile(self.f)

		arch = elff.get_machine_arch()
		if arch == "x64":
			cs_arch = CS_ARCH_X86
			cs_mode = CS_MODE_64
		elif arch == "x86":
			cs_arch = CS_ARCH_X86
			cs_mode = CS_MODE_32
		else:
			print("ELF architecture '%s' currently not supported" % arch)
			return

		""" Initialize capstone """
		self.md = Cs(cs_arch, cs_mode)

		s = elff.get_section(1)
		self.align = s['sh_addr'] - s['sh_offset']

		s = elff.get_section_by_name('.plt')
		if s:
			print('.plt')
			self.plt_start, self.plt_end = s['sh_addr'], s['sh_addr']+s['sh_size']
			self.plti = self.plt_start + 16
			print('0x%x 0x%x' % (self.plt_start, self.plt_end))

			s = elff.get_section_by_name('.dynsym')
			if s:
				print(s.name)
				syms = self.parse_symbols(s)
				if self.to_look:
					self.f.close()
					return syms
			else:
				print('No Dynamic Symbols table (.dynsym)')

			s = elff.get_section_by_name('.symtab')
			if s:
				print(s.name)
				self.parse_symbols(s)
			else:
				print('No Symbols Table (.symtab)')
		else:
			print('No plt table (.plt)')

		self.f.close()
		return self.plts


def find_dynamic_libs_needed(f):
	popen = subprocess.Popen(['ldd', f], stdout=subprocess.PIPE)
	(o, e) = popen.communicate()
	for line in o.split('\n'):
		if 'libc' in line:
			return line.split(' ')[2]


def main():
	if len(sys.argv) == 2:
		fgc = Flow_Graph_Creator(sys.argv[1])
		plts = fgc.parse_elf()
		libc = find_dynamic_libs_needed(sys.argv[1])

		print '\n'*2 + 'Need to look for:',
		print(plts)
		print('\n'*5 + 'Analysing libc')

		fgc = Flow_Graph_Creator(libc, plts)
		syms = fgc.parse_elf()
		'''
		fil = open(sys.argv[2], 'w')
		for v in syms:
			fil.write(str(v[0]) +'\n')
		fil.flush()
		fil.close()
		'''

if __name__ == '__main__':
	main()
