/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidragba;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class GhidraGBALoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "GBA ROM";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Too small to contain header
		if(provider.length() < 0xc0)
			return loadSpecs;

		// Invalid magic byte
		if(provider.readByte(0xb2) != (byte)0x96)
			return loadSpecs;

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v4t", "default"), true));

		return loadSpecs;
	}

	private void defineIORegister(FlatProgramAPI api, long offset, int size, String name)
		throws Exception {
		Address address = api.toAddr(offset);
		api.createLabel(address, name, true);
		switch (size) {
			case 1:
				api.createByte(address);
				break;
			case 2:
				api.createWord(address);
				break;
			case 4:
				api.createDWord(address);
				break;
		}
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		Memory mem = program.getMemory();
		FlatProgramAPI api = new FlatProgramAPI(program);

		try {
			// Memory map
			MemoryBlock wram = mem.createUninitializedBlock("WRAM", api.toAddr(0x02000000), 0x40000, false);
			wram.setPermissions(true, true, true);

			MemoryBlock iram = mem.createUninitializedBlock("IRAM", api.toAddr(0x03000000), 0x08000, false);
			iram.setPermissions(true, true, true);

			MemoryBlock io = mem.createUninitializedBlock("IO", api.toAddr(0x04000000), 0x003ff, false);
			io.setPermissions(true, true, false);
			io.setVolatile(true);

			MemoryBlock pal = mem.createUninitializedBlock("PAL", api.toAddr(0x05000000), 0x00400, false);
			pal.setPermissions(true, true, false);

			MemoryBlock vram = mem.createUninitializedBlock("VRAM", api.toAddr(0x06000000), 0x18000, false);
			vram.setPermissions(true, true, true);

			MemoryBlock obj = mem.createUninitializedBlock("OBJ", api.toAddr(0x07000000), 0x400, false);
			obj.setPermissions(true, true, false);

			MemoryBlock rom = mem.createInitializedBlock("ROM", api.toAddr(0x08000000), provider.getInputStream(0), 0x1000000, monitor, false);
			rom.setPermissions(true, false, true);

			// Entry point
			api.addEntryPoint(api.toAddr(0x08000000));
			api.createFunction(api.toAddr(0x08000000), "_entry");

			// Create GBA I/O Map
			defineIORegister(api, 0x04000000, 2, "DISPCNT");
			defineIORegister(api, 0x04000002, 2, "GREENSWAP");
			defineIORegister(api, 0x04000004, 2, "DISPSTAT");
			defineIORegister(api, 0x04000006, 2, "VCOUNT");
			defineIORegister(api, 0x04000008, 2, "BG0CNT");
			defineIORegister(api, 0x0400000A, 2, "BG1CNT");
			defineIORegister(api, 0x0400000C, 2, "BG2CNT");
			defineIORegister(api, 0x0400000E, 2, "BG3CNT");
			defineIORegister(api, 0x04000010, 2, "BG0HOFS");
			defineIORegister(api, 0x04000012, 2, "BG0VOFS");
			defineIORegister(api, 0x04000014, 2, "BG1HOFS");
			defineIORegister(api, 0x04000016, 2, "BG1VOFS");
			defineIORegister(api, 0x04000018, 2, "BG2HOFS");
			defineIORegister(api, 0x0400001A, 2, "BG2VOFS");
			defineIORegister(api, 0x0400001C, 2, "BG3HOFS");
			defineIORegister(api, 0x0400001E, 2, "BG3VOFS");
			defineIORegister(api, 0x04000020, 2, "BG2PA");
			defineIORegister(api, 0x04000022, 2, "BG2PB");
			defineIORegister(api, 0x04000024, 2, "BG2PC");
			defineIORegister(api, 0x04000026, 2, "BG2PD");
			defineIORegister(api, 0x04000028, 4, "BG2X");
			defineIORegister(api, 0x0400002C, 4, "BG2Y");
			defineIORegister(api, 0x04000030, 2, "BG3PA");
			defineIORegister(api, 0x04000032, 2, "BG3PB");
			defineIORegister(api, 0x04000034, 2, "BG3PC");
			defineIORegister(api, 0x04000036, 2, "BG3PD");
			defineIORegister(api, 0x04000038, 4, "BG3X");
			defineIORegister(api, 0x0400003C, 4, "BG3Y");
			defineIORegister(api, 0x04000040, 2, "WIN0H");
			defineIORegister(api, 0x04000042, 2, "WIN1H");
			defineIORegister(api, 0x04000044, 2, "WIN0V");
			defineIORegister(api, 0x04000046, 2, "WIN1V");
			defineIORegister(api, 0x04000048, 2, "WININ");
			defineIORegister(api, 0x0400004A, 2, "WINOUT");
			defineIORegister(api, 0x0400004C, 2, "MOSAIC");
			defineIORegister(api, 0x04000050, 2, "BLDCNT");
			defineIORegister(api, 0x04000052, 2, "BLDALPHA");
			defineIORegister(api, 0x04000054, 2, "BLDY");
			defineIORegister(api, 0x04000060, 2, "SOUND1CNT_L");
			defineIORegister(api, 0x04000062, 2, "SOUND1CNT_H");
			defineIORegister(api, 0x04000064, 2, "SOUND1CNT_X");
			defineIORegister(api, 0x04000068, 2, "SOUND2CNT_L");
			defineIORegister(api, 0x0400006C, 2, "SOUND2CNT_H");
			defineIORegister(api, 0x04000070, 2, "SOUND3CNT_L");
			defineIORegister(api, 0x04000072, 2, "SOUND3CNT_H");
			defineIORegister(api, 0x04000074, 2, "SOUND3CNT_X");
			defineIORegister(api, 0x04000078, 2, "SOUND4CNT_L");
			defineIORegister(api, 0x0400007C, 2, "SOUND4CNT_H");
			defineIORegister(api, 0x04000080, 2, "SOUNDCNT_L");
			defineIORegister(api, 0x04000082, 2, "SOUNDCNT_H");
			defineIORegister(api, 0x04000084, 2, "SOUNDCNT_X");
			defineIORegister(api, 0x04000088, 2, "SOUNDBIAS");
			defineIORegister(api, 0x04000090, 2, "WAVE_RAM0_L");
			defineIORegister(api, 0x04000092, 2, "WAVE_RAM0_H");
			defineIORegister(api, 0x04000094, 2, "WAVE_RAM1_L");
			defineIORegister(api, 0x04000096, 2, "WAVE_RAM1_H");
			defineIORegister(api, 0x04000098, 2, "WAVE_RAM2_L");
			defineIORegister(api, 0x0400009A, 2, "WAVE_RAM2_H");
			defineIORegister(api, 0x0400009C, 2, "WAVE_RAM3_L");
			defineIORegister(api, 0x0400009E, 2, "WAVE_RAM3_H");
			defineIORegister(api, 0x040000A0, 4, "FIFO_A");
			defineIORegister(api, 0x040000A4, 4, "FIFO_B");
			defineIORegister(api, 0x040000B0, 4, "DMA0SAD");
			defineIORegister(api, 0x040000B4, 4, "DMA0DAD");
			defineIORegister(api, 0x040000B8, 2, "DMA0CNT_L");
			defineIORegister(api, 0x040000BA, 2, "DMA0CNT_H");
			defineIORegister(api, 0x040000BC, 4, "DMA1SAD");
			defineIORegister(api, 0x040000C0, 4, "DMA1DAD");
			defineIORegister(api, 0x040000C4, 2, "DMA1CNT_L");
			defineIORegister(api, 0x040000C6, 2, "DMA1CNT_H");
			defineIORegister(api, 0x040000C8, 4, "DMA2SAD");
			defineIORegister(api, 0x040000CC, 4, "DMA2DAD");
			defineIORegister(api, 0x040000D0, 2, "DMA2CNT_L");
			defineIORegister(api, 0x040000D2, 2, "DMA2CNT_H");
			defineIORegister(api, 0x040000D4, 4, "DMA3SAD");
			defineIORegister(api, 0x040000D8, 4, "DMA3DAD");
			defineIORegister(api, 0x040000DC, 2, "DMA3CNT_L");
			defineIORegister(api, 0x040000DE, 2, "DMA3CNT_H");
			defineIORegister(api, 0x04000100, 2, "TM0CNT_L");
			defineIORegister(api, 0x04000102, 2, "TM0CNT_H");
			defineIORegister(api, 0x04000104, 2, "TM1CNT_L");
			defineIORegister(api, 0x04000106, 2, "TM1CNT_H");
			defineIORegister(api, 0x04000108, 2, "TM2CNT_L");
			defineIORegister(api, 0x0400010A, 2, "TM2CNT_H");
			defineIORegister(api, 0x0400010C, 2, "TM3CNT_L");
			defineIORegister(api, 0x0400010E, 2, "TM3CNT_H");
			defineIORegister(api, 0x04000120, 2, "SIOMULTI0");
			defineIORegister(api, 0x04000122, 2, "SIOMULTI1");
			defineIORegister(api, 0x04000124, 2, "SIOMULTI2");
			defineIORegister(api, 0x04000126, 2, "SIOMULTI3");
			defineIORegister(api, 0x04000120, 4, "SIODATA32");
			defineIORegister(api, 0x04000128, 2, "SIOCNT");
			defineIORegister(api, 0x0400012A, 2, "SIODATA8");
			defineIORegister(api, 0x0400012A, 2, "SIOMLT_SEND");
			defineIORegister(api, 0x04000130, 2, "KEYINPUT");
			defineIORegister(api, 0x04000132, 2, "KEYCNT");
			defineIORegister(api, 0x04000134, 2, "RCNT");
			defineIORegister(api, 0x04000136, 2, "IR"); // 2?
			defineIORegister(api, 0x04000140, 2, "JOYCNT");
			defineIORegister(api, 0x04000150, 4, "JOY_RECV");
			defineIORegister(api, 0x04000154, 4, "JOY_TRANS");
			defineIORegister(api, 0x04000158, 2, "JOYSTAT");
			defineIORegister(api, 0x04000200, 2, "IE");
			defineIORegister(api, 0x04000202, 2, "IF");
			defineIORegister(api, 0x04000204, 2, "WAITCNT");
			defineIORegister(api, 0x04000208, 2, "IME");
			defineIORegister(api, 0x04000300, 1, "POSTFLG");
			defineIORegister(api, 0x04000301, 1, "HALTCNT");

		} catch (Exception e) {
			log.appendException(e);
		}
	}
}
