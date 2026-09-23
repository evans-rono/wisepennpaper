import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const root = path.resolve(process.env.UPLOAD_DIR || 'uploads');
fs.mkdirSync(root, { recursive: true });
const isObjectStorage = process.env.STORAGE_DRIVER && process.env.STORAGE_DRIVER !== 'local';
let s3;

async function objectClient() {
  if (!s3) {
    const { S3Client } = await import('@aws-sdk/client-s3');
    s3 = new S3Client({
      region: process.env.S3_REGION || 'auto',
      endpoint: process.env.S3_ENDPOINT || undefined,
      forcePathStyle: process.env.S3_FORCE_PATH_STYLE === 'on',
      credentials: process.env.S3_ACCESS_KEY_ID ? {
        accessKeyId: process.env.S3_ACCESS_KEY_ID,
        secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
      } : undefined,
    });
  }
  return s3;
}

export function objectKey(file) {
  const name = `${Date.now()}-${crypto.randomBytes(12).toString('hex')}${path.extname(file.filename)}`;
  return isObjectStorage ? `documents/${new Date().toISOString().slice(0, 10)}/${name}` : name;
}

export async function persistUpload(file) {
  const key = objectKey(file);
  if (!isObjectStorage) {
    const destination = path.join(root, key);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    await fs.promises.rename(file.path, destination);
    return { storedName: key, driver: 'local' };
  }
  const { PutObjectCommand } = await import('@aws-sdk/client-s3');
  const client = await objectClient();
  await client.send(new PutObjectCommand({
    Bucket: process.env.S3_BUCKET,
    Key: key,
    Body: fs.createReadStream(file.path),
    ContentType: file.mimetype,
    ServerSideEncryption: process.env.S3_SSE || undefined,
  }));
  await fs.promises.rm(file.path, { force: true });
  return { storedName: key, driver: process.env.STORAGE_DRIVER || 's3' };
}

export async function removeUpload(storedName) {
  if (!storedName) return;
  if (!isObjectStorage) return fs.promises.rm(path.join(root, storedName), { force: true });
  const { DeleteObjectCommand } = await import('@aws-sdk/client-s3');
  await (await objectClient()).send(new DeleteObjectCommand({ Bucket: process.env.S3_BUCKET, Key: storedName }));
}

export async function downloadUpload(storedName) {
  if (!isObjectStorage) return { type: 'path', value: path.join(root, storedName) };
  const { GetObjectCommand } = await import('@aws-sdk/client-s3');
  const result = await (await objectClient()).send(new GetObjectCommand({ Bucket: process.env.S3_BUCKET, Key: storedName }));
  return { type: 'stream', value: result.Body, contentType: result.ContentType };
}

export function storageConfig() {
  return { driver: isObjectStorage ? process.env.STORAGE_DRIVER : 'local', bucket: process.env.S3_BUCKET || null };
}
