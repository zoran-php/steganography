package controllers;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.WritableRaster;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.imageio.ImageIO;

/**
 *
 * @author Zoran Davidovic
 */
public class Steganography {
    
    /**
     * Get hidden text from image raster bytes
     * 
     * @param imageBytes Array of image bytes
     * @return Hidden text embedded in image
     * @see byte[]
     * @throws IOException
     * @throws DataFormatException
     */
    private String getHiddenText(byte[] imageBytes) throws IOException, DataFormatException {
        int textLength = 0;
        int offset  = 40;
        byte isCompressed = 0;
        for (int i = 0; i < 32; ++i) {
            textLength = (textLength << 1) | (imageBytes[i] & 1);
        }
        for (int i = 32; i < 40; ++i) {
            isCompressed = (byte) ((isCompressed << 1) | (imageBytes[i] & 1));
        }
        byte[] result = new byte[textLength];
        for (int y = 0; y < textLength; ++y) {
            for (int z = 0; z < 8; ++z, ++offset) {
                result[y] = (byte)((result[y] << 1) | (imageBytes[offset] & 1));
            }
        }
        if (isCompressed == 1) {
            result = this.decompress(result);
        }
        return new String(result);
    }
    
    /**
     * Add bytes to image raster bytes
     * 
     * @param imageBytes Byte array of image raster
     * @param addition Bytes to be added to image raster bytes
     * @param offset Offset for additional bytes
     * @return Image raster byte array with additional bytes in it
     * @throws IllegalArgumentException
     */
    private byte[] hideBytes(byte[] imageBytes, byte[] addition, int offset) {
        if (addition.length + offset > (imageBytes.length / 8)) {
            throw new IllegalArgumentException("File not long enough!");
        }
        for (int i = 0; i < addition.length; ++i) {
            int add = addition[i];
            for (int bit = 7; bit >= 0; --bit, ++offset) {
                int b = (add >>> bit) & 1;
                imageBytes[offset] = (byte)((imageBytes[offset] & 0xFE) | b);
            }
        }
        return imageBytes;
    }
    
    /**
     * Get byte array from buffered image writable raster
     * 
     * @param image BufferedImage
     * @return Byte array of buffered image writable raster
     */
    private byte[] getBufferedImageRasterBytes(BufferedImage image) {
        WritableRaster raster = image.getRaster();
        DataBufferByte buffer = (DataBufferByte)raster.getDataBuffer();
        return buffer.getData();
    }
    
    /**
     * Get buffered image user space
     * 
     * @param image Buffered image
     * @return Buffered image user space
     */
    private BufferedImage getUserSpace(BufferedImage image) {
        int width = image.getWidth();
        int height = image.getHeight();
        int type = BufferedImage.TYPE_3BYTE_BGR;
        BufferedImage bufferedImage = new BufferedImage(width, height, type);
        Graphics2D g2d = bufferedImage.createGraphics();
        g2d.drawRenderedImage(image, null);
        g2d.dispose();
        return bufferedImage;
    }
    
    /**
     * Add text to image
     * 
     * @param image Buffered image
     * @param text Text to be added to image
     * @return Image with hidden text in it
     * @throws IOException
     */
    private BufferedImage addText(BufferedImage image, String text) throws IOException {
        int isCompressed = 0;
        byte[] imageBytes = this.getBufferedImageRasterBytes(image);
        byte[] textBytes = text.getBytes();
        if((textBytes.length + 40) > (imageBytes.length / 8)){
            isCompressed = 1;
            textBytes = this.compress(textBytes);
        }
        byte[] ziped = ByteBuffer.allocate(1).put((byte)isCompressed).array();
        byte[] length = ByteBuffer.allocate(4).putInt(textBytes.length).array();
        this.hideBytes(imageBytes, length, 0);
        this.hideBytes(imageBytes, ziped, 32);
        this.hideBytes(imageBytes, textBytes, 40);
        return image;
    }
    
    /**
     * Hide text to image and save it to 'png' format
     * 
     * @param in Image in which text will be added
     * @param out Image that contains hidden text
     * @param text Text to be hidden
     * @throws IOException 
     */
    public void hideText(File in, File out, String text) throws IOException {
        BufferedImage newImage = this.getUserSpace(ImageIO.read(in));
        newImage = this.addText(newImage, text);
        ImageIO.write(newImage, "png", out);
    }
    
    /**
     * Retrieve hidden text from image
     * 
     * @param in Image with hidden text
     * @return Hidden text from image
     * @throws IOException 
     * @throws DataFormatException 
     */
    public String retrieveText(File in) throws IOException, DataFormatException {
        BufferedImage newImage = this.getUserSpace(ImageIO.read(in));
        byte[] imageBytes = this.getBufferedImageRasterBytes(newImage);
        return this.getHiddenText(imageBytes);
    }
    
    /**
     * Compress byte array
     * 
     * @param data
     * @return Compressed byte array
     * @throws IOException 
     */
    private byte[] compress(byte[] data) throws IOException {  
        Deflater deflater = new Deflater();
        deflater.setInput(data);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        deflater.finish();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();
        return output;
    }
    
    /**
     * Decompress byte array
     * 
     * @param data Byte array
     * @return Decompressed byte array
     * @throws IOException
     * @throws DataFormatException 
     */
    public byte[] decompress(byte[] data) throws IOException, DataFormatException {
        Inflater inflater = new Inflater();
        inflater.setInput(data);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();
        return output;
    }
    
}
