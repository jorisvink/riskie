
ENTRY(test_entry)

MEMORY
{
	ROM	(rx):	ORIGIN = 0x00000000, LENGTH = 2M
}

SECTIONS
{
	.text :
	{
		. = ALIGN(8);
		*(.text)
		*(.text*)
		. = ALIGN(8);
	} >ROM

	.rodata :
	{
		. = ALIGN(8);
		*(.rodata)
		*(.rodata*)
		. = ALIGN(8);
	} >ROM

	.data :
	{
		. = ALIGN(8);
		*(.data)
		*(.data*)
		. = ALIGN(8);
	} >ROM

	. = ALIGN(8);
	.bss :
	{
		*(.bss)
		*(.bss*)
		*(.COMMON)
	} >ROM
}
