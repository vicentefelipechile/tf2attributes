#if defined __sm_port64_ext_included
	#endinput
#endif
#define __sm_port64_ext_included

#pragma semicolon 1
#pragma newdecls required

const NumberType NumberType_Int64 = view_as<NumberType>(3);

#define Address64_Null {0, 0}

// we can't use enum structs in natives, "any var[2]" will be compatible with this though
enum struct Address64
{
	int low;
	int high;

	bool IsNull()
	{
		return !this.low && !this.high;
	}

	void Add(int a)
	{
		int iBuffer[2];
		iBuffer[0] = a;

		Port64_Add(this, iBuffer, this);
	}

	void Set(any value[2])
	{
		this.low = value[0];
		this.high = value[1];
	}

	bool Equals(Address64 other)
	{
		return this.low == other.low && this.high == other.high;
	}

	void AssertValid(int iMinValid = 0x10000) // 65536
	{
		if (!this.low && !this.high)
		{
			ThrowError("Received invalid address (NULL)");
		}
		if (!this.high)
		{
			if ((this.low >>> 31) == (iMinValid >>> 31) && ((this.low & 0x7FFFFFFF) < (iMinValid & 0x7FFFFFFF))
			|| (this.low >>> 31) < (iMinValid >>> 31))
				ThrowError("Received invalid address (0x%08X%08X), minimum = 0x%08X", this.high, this.low, iMinValid);
		}
	}

	// Get the address of an entity, offset is then added to the address
	void GetEntityAddress(int entity, int offset = 0)
	{
		Port64_GetEntityAddress(entity, this, offset);
	}

	any Load(int offset, NumberType numberType)
	{
		any output[2];
		Port64_LoadFromAddress(this, offset, numberType, output);

		return output[0];
	}

	// Store the value to the address of `this`
	void Store(int offset, any value, NumberType numberType)
	{
		any input[2];
		input[0] = value;

		Port64_StoreToAddress(this, offset, numberType, input);
	}

	void DereferencePointer(int offset, any output[2])
	{
		Port64_LoadFromAddress(this, offset, NumberType_Int64, output);
	}

	void StorePointer(int offset, any input[2])
	{
		Port64_StoreToAddress(this, offset, NumberType_Int64, input);
	}

	int LoadString(char[] buffer, int maxlen, int offset = 0)
	{
		if (!this.low && !this.high)
		{
			LogError("Failed to load string from address: Address is null");
			return 0;
		}

		int c;
		int ch[2];

		if (offset > 0)
		{
			Address64 address;

			address.Set(this);
			address.Add(offset);

			do {
				Port64_LoadFromAddress(address, c, NumberType_Int8, ch);
				buffer[c] = view_as<char>(ch[0]);
			} while (ch[0] && ++c < maxlen - 1);

			return c;
		}

		do {
			Port64_LoadFromAddress(this, c, NumberType_Int8, ch);
			buffer[c] = view_as<char>(ch[0]);
		} while (ch[0] && ++c < maxlen - 1);

		return c;
	}
}

// returns how many bytes a pointer has
native int Port64_PointerBytes();

native void Port64_GetEntityAddress(int entity, any outputAddr[2], int offset = 0);

// conversions with pseudoaddress
native void Port64_FromPseudoAddress(Address pseudo, any outputAddr[2]);
native Address Port64_ToPseudoAddress(any addr[2]);

// load and store to address. offset is a 32 bit int for pointer arithmetic purposes
native void Port64_LoadFromAddress(any addr[2], int offset, NumberType type, any outputValue[2]);
native void Port64_StoreToAddress(any addr[2], int offset, NumberType type, any input[2]);

// operations
native void Port64_Add(any a[2], any b[2], any output[2]);
native void Port64_Sub(any a[2], any b[2], any output[2]);
native void Port64_Mul(any a[2], any b[2], any output[2]);
native void Port64_Div(any a[2], any b[2], any output[2]);

public Extension __ext_sm_port64 =
{
	name = "port64",
	file = "port64.ext",
#if defined AUTOLOAD_EXTENSIONS
	autoload = 1,
#else
	autoload = 0,
#endif
#if defined REQUIRE_EXTENSIONS
	required = 1,
#else
	required = 0,
#endif
};

#if !defined REQUIRE_EXTENSIONS
public void __ext_sm_port64_SetNTVOptional()
{
	MarkNativeAsOptional("Port64_PointerBytes");
	MarkNativeAsOptional("Port64_GetEntityAddress");
	MarkNativeAsOptional("Port64_FromPseudoAddress");
	MarkNativeAsOptional("Port64_ToPseudoAddress");
	MarkNativeAsOptional("Port64_LoadFromAddress");
	MarkNativeAsOptional("Port64_StoreToAddress");
	MarkNativeAsOptional("Port64_Add");
	MarkNativeAsOptional("Port64_Sub");
	MarkNativeAsOptional("Port64_Mul");
	MarkNativeAsOptional("Port64_Div");
}
#endif
