
ENTRY(test_entry)

MEMORY
{
	RAM	(rx):	ORIGIN = 0x80000000, LENGTH = 2M
}

SECTIONS
{
	.text :
	{
		. = ALIGN(8);
		*(.text)
		*(.text*)
		. = ALIGN(8);
	} >RAM

	.rodata :
	{
		. = ALIGN(8);
		*(.rodata)
		*(.rodata*)
		. = ALIGN(8);
	} >RAM

	.data :
	{
		. = ALIGN(8);
		*(.data)
		*(.data*)
		. = ALIGN(8);
	} >RAM

	. = ALIGN(8);
	.bss :
	{
		*(.bss)
		*(.bss*)
		*(.COMMON)
	} >RAM
}
