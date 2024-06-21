namespace RePak.Tests;

using System.IO;
using System.Text;

public class UnitTest1
{
    [Fact]
    public void TestFinalizer()
    {
        RePakInterop.pak_setup_allocator();

        var stream = new MemoryStream();

        using (PakBuilder builder = new PakBuilder())
        {
            using (var writer = builder.Writer(stream))
            {
                writer.WriteFile("a_file.txt", Encoding.ASCII.GetBytes("some file contents\n"));
                writer.WriteIndex();
            }
            Console.WriteLine($"Bytes written={stream.Length}");
        }

        using (PakBuilder builder = new PakBuilder())
        {
            using (var reader = builder.Reader(stream)) {
                reader.Get(stream, "a_file.txt");
            }
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        Console.WriteLine("huh");

        RePakInterop.pak_teardown_allocator();
    }

    [Fact]
    public void TestWritePak()
    {
        Console.WriteLine("Writing pak");
        using (FileStream stream = new FileStream("output2.pak", FileMode.Create))
        {
            var builder = new RePak.PakBuilder();
            var pak_writer = builder.Writer(stream);
            pak_writer.WriteFile("a_file.txt", Encoding.ASCII.GetBytes("some file contents\n"));
            pak_writer.WriteFile("another_file.txt", Encoding.ASCII.GetBytes("lorem ipsum\ndolor sit\n"));
            pak_writer.WriteFile("nested/file.txt", Encoding.ASCII.GetBytes("hello world\n"));
            pak_writer.WriteIndex();
        }
        Console.WriteLine("Reading pak");
        using (FileStream stream = new FileStream("output2.pak", FileMode.Open))
        {
            var builder = new RePak.PakBuilder();
            var pak_reader = builder.Reader(stream);
            foreach (var file in pak_reader.Files())
            {
                Console.WriteLine($"File: {file}");
                var bytes = pak_reader.Get(stream, file);
                Console.WriteLine($"Contents: {Encoding.ASCII.GetString(bytes)}");
            }
        }
    }
}
