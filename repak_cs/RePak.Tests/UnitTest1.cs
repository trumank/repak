namespace RePak.Tests;

using System.IO;
using System.Text;

public class UnitTest1
{
    [Fact]
    public void TestFinalizer()
    {
        RePakInterop.pak_setup_allocator();

        var key = Convert.FromBase64String("lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=");

        using (PakBuilder builder = new PakBuilder())
        {
            builder.Compression(new Compression[] { Compression.Zlib });
            using (var stream = new FileStream("output.pak", FileMode.Create))
            {
                using (var writer = builder.Writer(stream))
                {
                    writer.WriteFile("a_file1.txt", Encoding.ASCII.GetBytes("some file contents"));
                    writer.WriteFile("a_file2.txt", Encoding.ASCII.GetBytes("another file with contents"));
                    writer.WriteFile("a_file3.txt", Encoding.ASCII.GetBytes("last file with some contents"));
                    writer.WriteFile("a_file4.txt", Encoding.ASCII.GetBytes("lol jk one more"));
                    writer.WriteIndex();
                }
                Console.WriteLine($"Bytes written={stream.Length}");
            }
        }

        using (PakBuilder builder = new PakBuilder())
        {
            using (var fileStream = new FileStream("../../../../../repak/tests/packs/pack_v11_compress_encrypt_encryptindex.pak", FileMode.Open))
            {
                builder.Key(key);
                using (var reader = builder.Reader(fileStream))
                {
                    foreach (var file in reader.Files())
                    {
                        Console.WriteLine($"File={file} Contents={Encoding.ASCII.GetString(reader.Get(fileStream, file))}");
                    }
                }
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
