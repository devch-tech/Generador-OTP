package org.example;

import java.nio.ByteBuffer;
import java.security.Key;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

class TOTPGenerator {

    private static final String SECRET_KEY = "JBSWY3DPEHPK3PXP"; // Secreto en Base32
    private static final int INTERVAL = 30; // Duración en segundos del OTP
    private static final int DIGITS = 6; // Número de dígitos del OTP

    public static void main(String[] args) {
        long currentTime = System.currentTimeMillis() / 1000L;
        String otp = generateTOTP(SECRET_KEY, currentTime);
        System.out.println("Tu OTP es: " + otp);
    }

    private static String generateTOTP(String secretKey, long currentTime) {
        try {
            // Convertimos la clave secreta de Base32 a bytes
            byte[] decodedKey = Base64.getDecoder().decode(secretKey);

            // Creamos el timestamp ajustado al intervalo de tiempo
            long time = currentTime / INTERVAL;
            byte[] timeBytes = ByteBuffer.allocate(8).putLong(time).array();

            // Usamos HMAC-SHA256 para generar el hash
            Key key = new SecretKeySpec(decodedKey, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);

            byte[] hash = mac.doFinal(timeBytes);

            // Extraemos un número de 6 dígitos del hash
            int offset = hash[hash.length - 1] & 0xF;
            int binary =
                    ((hash[offset] & 0x7F) << 24) |
                            ((hash[offset + 1] & 0xFF) << 16) |
                            ((hash[offset + 2] & 0xFF) << 8) |
                            (hash[offset + 3] & 0xFF);

            int otp = binary % (int) Math.pow(10, DIGITS);

            // Aseguramos que el OTP siempre tenga 6 dígitos, rellenando con ceros si es necesario
            return String.format("%06d", otp);
        } catch (Exception e) {
            throw new RuntimeException("Error al generar el OTP", e);
        }
    }
}