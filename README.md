# tf2attributes x64 port (Linux only)

This exists in case Valve happens to kill off x86 servers and we don't yet have a better way to handle addresses.

## Requirements

Build SourceMod using [alliedmodders/sourcemod/#2159](https://github.com/alliedmodders/sourcemod/pull/2159)

My fork of Port64 [Malifox/port64](https://github.com/Malifox/port64)
- You may need to recompile any plugins previously using the original Port64 include, no code changes needed. I added an optional offset to Port64_GetEntityAddress to remove the additional Port64_Add step and native overhead. I didn't really think I would be porting the entirety of tf2attributes at the time and kind of hoped a more official solution would come along. Not really sure what to do about the additional methods I added to Address64 either in the event Valve deletes x86 servers and people actually need to use this and I made things messier by having a fork.

## Notes

The following natives will require changes to be made to the plugin that uses them due to passing an array(Address64):
- TF2Attrib_GetByName
- TF2Attrib_GetByDefIndex
- TF2Attrib_SetDefIndex
- TF2Attrib_GetDefIndex
- TF2Attrib_SetValue
- TF2Attrib_GetValue
- TF2Attrib_SetRefundableCurrency
- TF2Attrib_GetRefundableCurrency

I didn't test the heap-allocated management of non-networked attributes yet.