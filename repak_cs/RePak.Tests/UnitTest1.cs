namespace RePak.Tests;

using System.IO;
using System.Text;

public class UnitTest1
{
    [Fact]
    public void TestFinalizer()
    {
        RePak.PakBuilder? builder = null;
        for (var i = 0; i < 2; i++)
        {
            builder = new RePak.PakBuilder();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        Console.WriteLine("huh");
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
            foreach (var file in pak_reader.Files()) {
                Console.WriteLine($"File: {file}");
                var bytes = pak_reader.Get(stream, file);
                Console.WriteLine($"Contents: {Encoding.ASCII.GetString(bytes)}");
            }
        }
    }
}
