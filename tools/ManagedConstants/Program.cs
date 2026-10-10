using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;

if (args.Length is < 1 or > 2)
    throw new ArgumentException("usage: ManagedConstants <managed-pe> [output-json]");

using var stream = File.OpenRead(args[0]);
using var pe = new PEReader(stream);
var reader = pe.GetMetadataReader();
var result = new List<object>();

foreach (var handle in reader.TypeDefinitions)
{
    TypeDefinition type;
    try
    {
        type = reader.GetTypeDefinition(handle);
        if (!IsEnum(reader, type.BaseType))
            continue;
    }
    catch (BadImageFormatException)
    {
        continue;
    }

    var fields = new List<object>();
    foreach (var fieldHandle in type.GetFields())
    {
        try
        {
            var field = reader.GetFieldDefinition(fieldHandle);
            if (!field.Attributes.HasFlag(FieldAttributes.Literal))
                continue;
            var constantHandle = field.GetDefaultValue();
            if (constantHandle.IsNil)
                continue;
            var constant = reader.GetConstant(constantHandle);
            fields.Add(new
            {
                name = reader.GetString(field.Name),
                type_code = constant.TypeCode.ToString(),
                value = ReadConstant(reader, constant),
            });
        }
        catch (BadImageFormatException)
        {
            continue;
        }
    }

    try
    {
        var ns = reader.GetString(type.Namespace);
        var name = reader.GetString(type.Name);
        result.Add(new { @namespace = ns, name, fields });
    }
    catch (BadImageFormatException)
    {
        continue;
    }
}

var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
if (args.Length == 2)
    File.WriteAllText(args[1], json + Environment.NewLine);
else
    Console.WriteLine(json);

static bool IsEnum(MetadataReader reader, EntityHandle handle)
{
    if (handle.Kind == HandleKind.TypeReference)
    {
        var type = reader.GetTypeReference((TypeReferenceHandle)handle);
        return reader.GetString(type.Namespace) == "System" && reader.GetString(type.Name) == "Enum";
    }
    if (handle.Kind == HandleKind.TypeDefinition)
    {
        var type = reader.GetTypeDefinition((TypeDefinitionHandle)handle);
        return reader.GetString(type.Namespace) == "System" && reader.GetString(type.Name) == "Enum";
    }
    return false;
}

static object ReadConstant(MetadataReader reader, Constant constant)
{
    var blob = reader.GetBlobReader(constant.Value);
    return constant.TypeCode switch
    {
        ConstantTypeCode.Boolean => blob.ReadByte() != 0,
        ConstantTypeCode.Char => (char)blob.ReadUInt16(),
        ConstantTypeCode.SByte => blob.ReadSByte(),
        ConstantTypeCode.Byte => blob.ReadByte(),
        ConstantTypeCode.Int16 => blob.ReadInt16(),
        ConstantTypeCode.UInt16 => blob.ReadUInt16(),
        ConstantTypeCode.Int32 => blob.ReadInt32(),
        ConstantTypeCode.UInt32 => blob.ReadUInt32(),
        ConstantTypeCode.Int64 => blob.ReadInt64(),
        ConstantTypeCode.UInt64 => blob.ReadUInt64(),
        ConstantTypeCode.Single => blob.ReadSingle(),
        ConstantTypeCode.Double => blob.ReadDouble(),
        ConstantTypeCode.String => blob.ReadUTF16(blob.RemainingBytes),
        ConstantTypeCode.NullReference => null!,
        _ => throw new NotSupportedException($"unsupported constant type {constant.TypeCode}"),
    };
}

