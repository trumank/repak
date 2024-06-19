namespace RePak;

using System;
using System.IO;
using System.Runtime.InteropServices;

public enum Version : byte
{
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,
    V7 = 7,
    V8A = 8,
    V8B = 9,
    V9 = 10,
    V10 = 11,
    V11 = 12
}

public enum Compression : byte
{
    Zlib,
    Gzip,
    Oodle,
    Zstd
}


public class PakBuilder
{
    private IntPtr _handle;

    public PakBuilder()
    {
        _handle = RePakInterop.pak_builder_new();
    }

    ~PakBuilder()
    {
        if (_handle == IntPtr.Zero) return;

        RePakInterop.pak_builder_drop(_handle);
    }

    //public PakBuilder Key(Aes256 key)
    //{
    //    _handle = PakBuilderInterop.pak_builder_key(_handle, key);
    //    return this;
    //}

    //public PakBuilder Compression(Compression[] compressions)
    //{
    //    IntPtr compressionsPtr = Marshal.AllocHGlobal(compressions.Length * Marshal.SizeOf<Compression>());
    //    Marshal.Copy(compressions, 0, compressionsPtr, compressions.Length);
    //    _handle = PakBuilderInterop.pak_builder_compression(_handle, compressionsPtr, compressions.Length);
    //    Marshal.FreeHGlobal(compressionsPtr);
    //    return this;
    //}

    public PakWriter Writer(Stream stream, Version version = Version.V11, string mountPoint = "../../../", ulong pathHashSeed = 0)
    {
        if (_handle == IntPtr.Zero) throw new Exception("PakBuilder handle invalid");

        var streamCtx = new RePakInterop.StreamCallbacks
        {
            Context = GCHandle.ToIntPtr(GCHandle.Alloc(stream)),
            ReadCb = StreamCallbacks.ReadCallback,
            WriteCb = StreamCallbacks.WriteCallback,
            SeekCb = StreamCallbacks.SeekCallback,
            FlushCb = StreamCallbacks.FlushCallback
        };

        IntPtr writerHandle = RePakInterop.pak_builder_writer(_handle, streamCtx, version, mountPoint, pathHashSeed);
        _handle = IntPtr.Zero; // pak_builder_writer consumes the builder
        return new PakWriter(writerHandle, stream);
    }

    public PakReader Reader(Stream stream)
    {
        if (_handle == IntPtr.Zero) throw new Exception("PakBuilder handle invalid");

        var streamCtx = new RePakInterop.StreamCallbacks
        {
            Context = GCHandle.ToIntPtr(GCHandle.Alloc(stream)),
            ReadCb = StreamCallbacks.ReadCallback,
            WriteCb = StreamCallbacks.WriteCallback,
            SeekCb = StreamCallbacks.SeekCallback,
            FlushCb = StreamCallbacks.FlushCallback
        };

        IntPtr readerHandle = RePakInterop.pak_builder_reader(_handle, streamCtx);
        _handle = IntPtr.Zero; // pak_builder_reader consumes the builder
        if (readerHandle == IntPtr.Zero) throw new Exception("Failed to create PakReader");
        return new PakReader(readerHandle, stream);
    }
}

public class PakWriter : IDisposable
{
    private IntPtr _handle;
    private Stream _stream;

    public PakWriter(IntPtr handle, Stream stream)
    {
        _handle = handle;
        _stream = stream;
    }

    public void WriteFile(string path, byte[] data)
    {
        int result = RePakInterop.pak_writer_write_file(_handle, path, data, data.Length);
        if (result != 0)
        {
            throw new Exception("Failed to write file");
        }
    }

    public void WriteIndex()
    {
        int result = RePakInterop.pak_writer_write_index(_handle);
        if (result != 0)
        {
            throw new Exception("Failed to write index");
        }
    }

    public void Dispose()
    {
    }
}

public class PakReader : IDisposable
{
    private IntPtr _handle;

    public PakReader(IntPtr handle, Stream stream)
    {
        _handle = handle;
    }

    public byte[] Get(Stream stream, string path)
    {
        var streamCtx = new RePakInterop.StreamCallbacks
        {
            Context = GCHandle.ToIntPtr(GCHandle.Alloc(stream)),
            ReadCb = StreamCallbacks.ReadCallback,
            WriteCb = StreamCallbacks.WriteCallback,
            SeekCb = StreamCallbacks.SeekCallback,
            FlushCb = StreamCallbacks.FlushCallback
        };

        IntPtr bufferPtr;
        int length;
        int result = RePakInterop.pak_reader_get(_handle, path, streamCtx, out bufferPtr, out length);

        if (result != 0)
        {
            throw new Exception("Failed to get file");
        }

        byte[] buffer = new byte[length];
        Marshal.Copy(bufferPtr, buffer, 0, length);
        // TODO free buffer
        return buffer;
    }

    public string[] Files()
    {
        IntPtr filesPtr = RePakInterop.pak_reader_files(_handle);
        var files = new List<string>();
        int index = 0;
        IntPtr currentPtr = Marshal.ReadIntPtr(filesPtr);
        while (currentPtr != IntPtr.Zero)
        {
            files.Add(Marshal.PtrToStringAnsi(currentPtr));
            index++;
            currentPtr = Marshal.ReadIntPtr(filesPtr, index * IntPtr.Size);
        }
        // TODO free buffer
        return files.ToArray();
    }

    public void Dispose()
    {
    }
}


public class StreamCallbacks
{
    public static long ReadCallback(IntPtr context, IntPtr buffer, ulong bufferLen)
    {
        var stream = (Stream)GCHandle.FromIntPtr(context).Target;
        try
        {
            byte[] bufferManaged = new byte[bufferLen];
            int bytesRead = stream.Read(bufferManaged, 0, (int)bufferLen);
            Marshal.Copy(bufferManaged, 0, buffer, bytesRead);
            return bytesRead;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error during read {e}");
            return -1;
        }
    }

    public static int WriteCallback(IntPtr context, IntPtr buffer, int bufferLen)
    {
        var stream = (Stream)GCHandle.FromIntPtr(context).Target;
        var bufferManaged = new byte[bufferLen];
        Marshal.Copy(buffer, bufferManaged, 0, bufferLen);

        try
        {
            stream.Write(bufferManaged, 0, bufferLen);
            return bufferLen;
        }
        catch
        {
            return 0; // or handle error
        }
    }

    public static ulong SeekCallback(IntPtr context, long offset, int origin)
    {
        var stream = (Stream)GCHandle.FromIntPtr(context).Target;
        try
        {
            long newPosition = stream.Seek(offset, (SeekOrigin)origin);
            return (ulong)newPosition;
        }
        catch
        {
            return ulong.MaxValue; // or handle error
        }
    }

    public static int FlushCallback(IntPtr context)
    {
        var stream = (Stream)GCHandle.FromIntPtr(context).Target;
        try
        {
            stream.Flush();
            return 0; // success
        }
        catch
        {
            return 1; // or handle error
        }
    }
}
