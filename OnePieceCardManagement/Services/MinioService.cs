using Microsoft.Extensions.Options;
using Minio;
using Minio.DataModel.Args;
using Minio.Exceptions;
using OnePieceCardManagement.Configuration;

namespace OnePieceCardManagement.Services
{
    public interface IMinioService
    {
        Task<string> UploadFileAsync(IFormFile file, string fileName, string bucketName);
        Task<string> UploadFileAsync(Stream fileStream, string fileName, string bucketName, string contentType);
        Task<bool> DeleteFileAsync(string fileUrl);
        Task<Stream> GetFileAsync(string fileName, string bucketName);
        Task<bool> BucketExistsAsync(string bucketName);
        Task CreateBucketAsync(string bucketName);
        Task<bool> FileExistsAsync(string fileName, string bucketName);
        Task<string> GetPreSignedUrlAsync(string fileName, string bucketName, int expiry = 3600);
        string GetPublicUrl(string fileName, string bucketName);
    }

    public class MinioService : IMinioService
    {
        private readonly IMinioClient _minioClient;
        private readonly MinioConfiguration _config;
        private readonly ILogger<MinioService> _logger;

        public MinioService(
            IMinioClient minioClient,
            IOptions<MinioConfiguration> config,
            ILogger<MinioService> logger)
        {
            _minioClient = minioClient;
            _config = config.Value;
            _logger = logger;
        }

        public async Task<string> UploadFileAsync(IFormFile file, string fileName, string bucketName)
        {
            try
            {
                // Ensure bucket exists
                await EnsureBucketExistsAsync(bucketName);

                // Generate unique filename if needed
                var uniqueFileName = GenerateUniqueFileName(fileName);

                using var stream = file.OpenReadStream();

                var putObjectArgs = new PutObjectArgs()
                    .WithBucket(bucketName)
                    .WithObject(uniqueFileName)
                    .WithStreamData(stream)
                    .WithObjectSize(file.Length)
                    .WithContentType(file.ContentType);

                await _minioClient.PutObjectAsync(putObjectArgs);

                _logger.LogInformation("File uploaded successfully: {FileName} to bucket: {Bucket}",
                    uniqueFileName, bucketName);

                // Return the public URL
                return GetPublicUrl(uniqueFileName, bucketName);
            }
            catch (MinioException ex)
            {
                _logger.LogError(ex, "MinIO error uploading file: {FileName}", fileName);
                throw new InvalidOperationException($"Failed to upload file: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading file: {FileName}", fileName);
                throw;
            }
        }

        public async Task<string> UploadFileAsync(Stream fileStream, string fileName, string bucketName, string contentType)
        {
            try
            {
                // Ensure bucket exists
                await EnsureBucketExistsAsync(bucketName);

                var uniqueFileName = GenerateUniqueFileName(fileName);

                var putObjectArgs = new PutObjectArgs()
                    .WithBucket(bucketName)
                    .WithObject(uniqueFileName)
                    .WithStreamData(fileStream)
                    .WithObjectSize(fileStream.Length)
                    .WithContentType(contentType);

                await _minioClient.PutObjectAsync(putObjectArgs);

                _logger.LogInformation("Stream uploaded successfully: {FileName} to bucket: {Bucket}",
                    uniqueFileName, bucketName);

                return GetPublicUrl(uniqueFileName, bucketName);
            }
            catch (MinioException ex)
            {
                _logger.LogError(ex, "MinIO error uploading stream: {FileName}", fileName);
                throw new InvalidOperationException($"Failed to upload file: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading stream: {FileName}", fileName);
                throw;
            }
        }

        public async Task<bool> DeleteFileAsync(string fileUrl)
        {
            try
            {
                // Extract bucket name and object name from URL
                var (bucketName, objectName) = ExtractBucketAndObjectFromUrl(fileUrl);

                if (string.IsNullOrEmpty(bucketName) || string.IsNullOrEmpty(objectName))
                {
                    _logger.LogWarning("Could not extract bucket and object from URL: {Url}", fileUrl);
                    return false;
                }

                // Check if file exists
                var exists = await FileExistsAsync(objectName, bucketName);
                if (!exists)
                {
                    _logger.LogWarning("File not found for deletion: {ObjectName} in bucket: {Bucket}",
                        objectName, bucketName);
                    return false;
                }

                var removeObjectArgs = new RemoveObjectArgs()
                    .WithBucket(bucketName)
                    .WithObject(objectName);

                await _minioClient.RemoveObjectAsync(removeObjectArgs);

                _logger.LogInformation("File deleted successfully: {ObjectName} from bucket: {Bucket}",
                    objectName, bucketName);
                return true;
            }
            catch (MinioException ex)
            {
                _logger.LogError(ex, "MinIO error deleting file: {Url}", fileUrl);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting file: {Url}", fileUrl);
                return false;
            }
        }

        public async Task<Stream> GetFileAsync(string fileName, string bucketName)
        {
            try
            {
                var memoryStream = new MemoryStream();

                var getObjectArgs = new GetObjectArgs()
                    .WithBucket(bucketName)
                    .WithObject(fileName)
                    .WithCallbackStream((stream) =>
                    {
                        stream.CopyTo(memoryStream);
                    });

                await _minioClient.GetObjectAsync(getObjectArgs);
                memoryStream.Position = 0;

                _logger.LogInformation("File retrieved successfully: {FileName} from bucket: {Bucket}",
                    fileName, bucketName);

                return memoryStream;
            }
            catch (MinioException ex)
            {
                _logger.LogError(ex, "MinIO error getting file: {FileName}", fileName);
                throw new InvalidOperationException($"Failed to get file: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting file: {FileName}", fileName);
                throw;
            }
        }

        public async Task<bool> BucketExistsAsync(string bucketName)
        {
            try
            {
                var bucketExistsArgs = new BucketExistsArgs()
                    .WithBucket(bucketName);

                return await _minioClient.BucketExistsAsync(bucketExistsArgs);
            }
            catch (MinioException ex)
            {
                _logger.LogError(ex, "MinIO error checking bucket existence: {Bucket}", bucketName);
                throw new InvalidOperationException($"Failed to check bucket: {ex.Message}", ex);
            }
        }

        public async Task CreateBucketAsync(string bucketName)
        {
            try
            {
                var makeBucketArgs = new MakeBucketArgs()
                    .WithBucket(bucketName);

                await _minioClient.MakeBucketAsync(makeBucketArgs);

                // Set bucket policy to allow public read access (optional)
                await SetBucketPolicyAsync(bucketName);

                _logger.LogInformation("Bucket created successfully: {Bucket}", bucketName);
            }
            catch (MinioException ex)
            {
                _logger.LogError(ex, "MinIO error creating bucket: {Bucket}", bucketName);
                throw new InvalidOperationException($"Failed to create bucket: {ex.Message}", ex);
            }
        }

        public async Task<bool> FileExistsAsync(string fileName, string bucketName)
        {
            try
            {
                var statObjectArgs = new StatObjectArgs()
                    .WithBucket(bucketName)
                    .WithObject(fileName);

                await _minioClient.StatObjectAsync(statObjectArgs);
                return true;
            }
            catch (ObjectNotFoundException)
            {
                return false;
            }
            catch (MinioException ex)
            {
                _logger.LogError(ex, "MinIO error checking file existence: {FileName}", fileName);
                return false;
            }
        }

        public async Task<string> GetPreSignedUrlAsync(string fileName, string bucketName, int expiry = 3600)
        {
            try
            {
                var presignedGetObjectArgs = new PresignedGetObjectArgs()
                    .WithBucket(bucketName)
                    .WithObject(fileName)
                    .WithExpiry(expiry);

                var url = await _minioClient.PresignedGetObjectAsync(presignedGetObjectArgs);

                _logger.LogInformation("Pre-signed URL generated for: {FileName}, expiry: {Expiry}s",
                    fileName, expiry);

                return url;
            }
            catch (MinioException ex)
            {
                _logger.LogError(ex, "MinIO error generating pre-signed URL: {FileName}", fileName);
                throw new InvalidOperationException($"Failed to generate pre-signed URL: {ex.Message}", ex);
            }
        }

        public string GetPublicUrl(string fileName, string bucketName)
        {
            // Costruisce l'URL pubblico basato sulla configurazione
            var publicUrl = _config.PublicUrl;

            if (string.IsNullOrEmpty(publicUrl))
            {
                // Se non c'è un URL pubblico configurato, usa l'endpoint MinIO
                var protocol = _config.UseSSL ? "https" : "http";
                publicUrl = $"{protocol}://{_config.Endpoint}";
            }

            return $"{publicUrl.TrimEnd('/')}/{bucketName}/{fileName}";
        }

        // Private helper methods
        private async Task EnsureBucketExistsAsync(string bucketName)
        {
            var exists = await BucketExistsAsync(bucketName);
            if (!exists)
            {
                await CreateBucketAsync(bucketName);
            }
        }

        private string GenerateUniqueFileName(string fileName)
        {
            var fileExtension = Path.GetExtension(fileName);
            var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileName);
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var randomString = Guid.NewGuid().ToString("N").Substring(0, 8);

            return $"{fileNameWithoutExtension}_{timestamp}_{randomString}{fileExtension}";
        }

        private (string bucketName, string objectName) ExtractBucketAndObjectFromUrl(string url)
        {
            try
            {
                var uri = new Uri(url);
                var segments = uri.AbsolutePath.Trim('/').Split('/');

                if (segments.Length >= 2)
                {
                    var bucketName = segments[0];
                    var objectName = string.Join("/", segments.Skip(1));
                    return (bucketName, objectName);
                }

                return (string.Empty, string.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing URL: {Url}", url);
                return (string.Empty, string.Empty);
            }
        }

        private async Task SetBucketPolicyAsync(string bucketName)
        {
            try
            {
                // Policy JSON per permettere lettura pubblica
                var policyJson = $@"{{
                    ""Version"": ""2012-10-17"",
                    ""Statement"": [
                        {{
                            ""Effect"": ""Allow"",
                            ""Principal"": {{
                                ""AWS"": [""*""]
                            }},
                            ""Action"": [
                                ""s3:GetBucketLocation"",
                                ""s3:ListBucket""
                            ],
                            ""Resource"": [""arn:aws:s3:::{bucketName}""]
                        }},
                        {{
                            ""Effect"": ""Allow"",
                            ""Principal"": {{
                                ""AWS"": [""*""]
                            }},
                            ""Action"": [""s3:GetObject""],
                            ""Resource"": [""arn:aws:s3:::{bucketName}/*""]
                        }}
                    ]
                }}";

                var setPolicyArgs = new SetPolicyArgs()
                    .WithBucket(bucketName)
                    .WithPolicy(policyJson);

                await _minioClient.SetPolicyAsync(setPolicyArgs);

                _logger.LogInformation("Public read policy set for bucket: {Bucket}", bucketName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to set bucket policy for: {Bucket}", bucketName);
            }
        }
    }
}
