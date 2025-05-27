/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/JSP_Servlet/Servlet.java to edit this template
 */
package servlet;

import dto.Cliente;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.json.JSONObject;

/**
 *
 * @author kiara
 */
@WebServlet(name = "Login", urlPatterns = {"/login"})
public class login extends HttpServlet {

    private EntityManagerFactory emf;
    private static final String DES_KEY = "12345678"; // Clave DES de 8 bytes

    @Override
    public void init() throws ServletException {
        emf = Persistence.createEntityManagerFactory("com.mycompany_Fact_war_1.0-SNAPSHOTPU");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        configurarCORS(response);
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED); // 405
        response.getWriter().write("{\"status\":\"error\", \"message\":\"Método GET no permitido\"}");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        configurarCORS(response);

        try {
            JSONObject requestData = leerJSON(request);
            String usuario = requestData.optString("usuario", "").trim();
            String clave = requestData.optString("clave", "").trim();

            if (usuario.isEmpty() || clave.isEmpty()) {
                enviarError(response, "Usuario y contraseña son requeridos");
                return;
            }

            // Cifrar la clave usando DES
            String claveCifrada = cifrarDES(clave);

            // Autenticar usuario
            Cliente usuarioEncontrado = autenticarUsuario(usuario, claveCifrada);

            if (usuarioEncontrado != null) {
                crearSesion(request, usuarioEncontrado);

                JSONObject respuesta = new JSONObject()
                        .put("status", "ok")
                        .put("message", "Login exitoso")
                        .put("usuario", usuarioEncontrado.getLogiClie())
                        .put("usuarioId", usuarioEncontrado.getCodiCLie())
                        .put("nombre", usuarioEncontrado.getNombClie())
                        .put("redirect", "principal.html");

                enviarRespuesta(response, respuesta);
            } else {
                enviarError(response, "Usuario o contraseña incorrectos");
            }

        } catch (Exception e) {
            enviarError(response, "Error interno del servidor");
        }
    }

    private Cliente autenticarUsuario(String usuario, String claveCifrada) {
        EntityManager em = emf.createEntityManager();
        try {
            return em.createQuery(
                    "SELECT c FROM Cliente c WHERE c.logiClie = :usuario AND c.passClie = :clave",
                    Cliente.class)
                    .setParameter("usuario", usuario)
                    .setParameter("clave", claveCifrada)
                    .getResultStream()
                    .findFirst()
                    .orElse(null);
        } finally {
            em.close();
        }
    }

    private void crearSesion(HttpServletRequest request, Cliente usuario) {
        HttpSession sesion = request.getSession();
        sesion.setAttribute("usuario", usuario);
        sesion.setAttribute("usuarioId", usuario.getCodiCLie());
        sesion.setAttribute("usuarioNombre", usuario.getNombClie());
    }

    private String cifrarDES(String texto) throws Exception {
        SecretKey key = new SecretKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] textoCifrado = cipher.doFinal(texto.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(textoCifrado);
    }

    private void configurarCORS(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
    }

    private JSONObject leerJSON(HttpServletRequest request) throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;
        try (BufferedReader reader = request.getReader()) {
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        return new JSONObject(sb.toString());
    }

    private void enviarRespuesta(HttpServletResponse response, JSONObject json) throws IOException {
        try (PrintWriter out = response.getWriter()) {
            out.print(json.toString());
        }
    }

    private void enviarError(HttpServletResponse response, String mensaje) throws IOException {
        JSONObject error = new JSONObject()
                .put("status", "error")
                .put("message", mensaje);
        enviarRespuesta(response, error);
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        configurarCORS(response);
        response.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    public void destroy() {
        if (emf != null && emf.isOpen()) {
            emf.close();
        }
    }
}