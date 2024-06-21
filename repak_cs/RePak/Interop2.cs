namespace RePak;

using System;
using System.IO;
using System.Runtime.InteropServices;

public class RePakInterop
{
    public const string NativeLib = "repak_bind";

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_setup_allocator();
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_teardown_allocator();

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_builder_new();

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_builder_drop(IntPtr builder);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_reader_drop(IntPtr reader);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_writer_drop(IntPtr writer);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pak_buffer_drop(IntPtr buffer, ulong length);

    //[DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    //public static extern IntPtr pak_builder_key(IntPtr builder, Aes256 key);
    //[DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    //public static extern IntPtr pak_builder_compression(IntPtr builder, IntPtr compressions, int count);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_builder_reader(IntPtr builder, StreamCallbacks ctx);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_builder_writer(IntPtr builder, StreamCallbacks ctx, Version version, string mount_point, ulong path_hash_seed = 0);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pak_reader_get(IntPtr reader, string path, StreamCallbacks ctx, out IntPtr buffer, out ulong length);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pak_reader_files(IntPtr reader);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pak_writer_write_file(IntPtr writer, string path, byte[] data, int data_len);
    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pak_writer_write_index(IntPtr writer);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate long ReadCallback(IntPtr context, IntPtr buffer, ulong bufferLen);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int WriteCallback(IntPtr context, IntPtr buffer, int bufferLen);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate ulong SeekCallback(IntPtr context, long offset, int origin);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int FlushCallback(IntPtr context);

    [StructLayout(LayoutKind.Sequential)]
    public struct StreamCallbacks
    {
        public IntPtr Context;
        public ReadCallback ReadCb;
        public WriteCallback WriteCb;
        public SeekCallback SeekCb;
        public FlushCallback FlushCb;
    }
}

