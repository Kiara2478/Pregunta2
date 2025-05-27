/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/JSP_Servlet/Servlet.java to edit this template
 */
package servlet;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import dao.ClienteJpaController;
import dto.Cliente;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author kiara
 */
@WebServlet(name = "RegistroServlet", urlPatterns = {"/registroservlet"})
public class RegistroServlet extends HttpServlet {

    private static final String SECRET_KEY = "12345678"; // 8 bytes para DES
    private static EntityManagerFactory emf;
    private ClienteJpaController personaDAO;
    private Gson gson;

    @Override
    public void init() throws ServletException {
        emf = Persistence.createEntityManagerFactory("com.mycompany_CriptoPract_war_1.0-SNAPSHOTPU");
        personaDAO = new ClienteJpaController(emf);
        gson = new Gson();
    }

    // Registro básico
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        configurarCORS(response);

        try {
            JsonObject jsonData = gson.fromJson(request.getReader(), JsonObject.class);

            if (!validarDatosBasicos(jsonData)) {
                enviarError(response, "Faltan datos requeridos: nombre, login y password");
                return;
            }

            String nombre = jsonData.get("nombre").getAsString().trim();
            String login = jsonData.get("login").getAsString().trim();
            String password = jsonData.get("password").getAsString();

            if (loginExiste(login)) {
                enviarError(response, "El nombre de usuario ya existe");
                return;
            }

            Cliente nuevaPersona = new Cliente();
            nuevaPersona.setNombClie(nombre);
            nuevaPersona.setLogiClie(login);
            nuevaPersona.setPassClie(cifrarDES(password));

            personaDAO.create(nuevaPersona);

            enviarRespuesta(response, "Usuario registrado exitosamente", nuevaPersona.getCodiCLie());

        } catch (Exception e) {
            e.printStackTrace();
            enviarError(response, "Error interno del servidor al registrar usuario");
        }
    }

    // Registro completo
    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        configurarCORS(response);

        try {
            JsonObject jsonData = gson.fromJson(request.getReader(), JsonObject.class);

            if (!validarDatosCompletos(jsonData)) {
                enviarError(response, "Faltan datos requeridos para registro completo");
                return;
            }

            String nombre = jsonData.get("nombre").getAsString().trim();
            String login = jsonData.get("login").getAsString().trim();
            String password = jsonData.get("password").getAsString();
            String dni = jsonData.get("dni").getAsString().trim();
            String fechaNacimiento = jsonData.get("fechaNacimiento").getAsString();
            String apPater = jsonData.get("Paterno").getAsString().trim();
            String amMater = jsonData.get("Materno").getAsString().trim();

            if (loginExiste(login)) {
                enviarError(response, "El nombre de usuario ya existe");
                return;
            }

            if (dniExiste(dni)) {
                enviarError(response, "El DNI ya está registrado");
                return;
            }

            Date fechaNaci = convertirFecha(fechaNacimiento);
            if (fechaNaci == null) {
                enviarError(response, "Formato de fecha inválido. Use YYYY-MM-DD");
                return;
            }

            Cliente nuevaPersona = new Cliente();
            nuevaPersona.setNombClie(nombre);
            nuevaPersona.setLogiClie(login);
            nuevaPersona.setPassClie(cifrarDES(password));
            nuevaPersona.setNdniClie(dni);
            nuevaPersona.setFechNaciClie(fechaNaci);
            nuevaPersona.setAppaClie(apPater);
            nuevaPersona.setApmaClie(amMater);

            personaDAO.create(nuevaPersona);

            enviarRespuesta(response, "Usuario registrado exitosamente con datos completos",
                    nuevaPersona.getCodiCLie());

        } catch (Exception e) {
            e.printStackTrace();
            enviarError(response, "Error interno del servidor al registrar usuario");
        }
    }

    // CORS
    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        configurarCORS(response);
        response.setStatus(HttpServletResponse.SC_OK);
    }

    private boolean validarDatosBasicos(JsonObject data) {
        return data.has("nombre") && !data.get("nombre").getAsString().trim().isEmpty()
                && data.has("login") && !data.get("login").getAsString().trim().isEmpty()
                && data.has("password") && !data.get("password").getAsString().isEmpty();
    }

    private boolean validarDatosCompletos(JsonObject data) {
        return validarDatosBasicos(data)
                && data.has("dni") && !data.get("dni").getAsString().trim().isEmpty()
                && data.has("fechaNacimiento") && !data.get("fechaNacimiento").getAsString().isEmpty()
                && data.has("Paterno") && !data.get("Paterno").getAsString().trim().isEmpty()
                && data.has("Materno") && !data.get("Materno").getAsString().trim().isEmpty();
    }

    private boolean loginExiste(String login) {
        try {
            List<Cliente> personas = personaDAO.findClienteEntities();
            for (Cliente p : personas) {
                if (login.equals(p.getLogiClie())) {
                    return true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean dniExiste(String dni) {
        try {
            List<Cliente> personas = personaDAO.findClienteEntities();
            for (Cliente p : personas) {
                if (dni.equals(p.getNdniClie())) {
                    return true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private Date convertirFecha(String fechaStr) {
        try {
            SimpleDateFormat formato = new SimpleDateFormat("yyyy-MM-dd");
            formato.setLenient(false);
            return formato.parse(fechaStr);
        } catch (ParseException e) {
            return null;
        }
    }

    private String cifrarDES(String texto) throws Exception {
        DESKeySpec desKeySpec = new DESKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] datosCifrados = cipher.doFinal(texto.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(datosCifrados);
    }

    private void enviarRespuesta(HttpServletResponse response, String mensaje, Integer userId)
            throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter out = response.getWriter();
        JsonObject obj = new JsonObject();
        obj.addProperty("status", "success");
        obj.addProperty("message", mensaje);
        if (userId != null) {
            obj.addProperty("userId", userId);
        }
        out.print(obj.toString());
        out.flush();
        out.close();
    }

    private void enviarError(HttpServletResponse response, String mensaje) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        PrintWriter out = response.getWriter();
        JsonObject obj = new JsonObject();
        obj.addProperty("status", "error");
        obj.addProperty("message", mensaje);
        out.print(obj.toString());
        out.flush();
        out.close();
    }

    private void configurarCORS(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
        response.setCharacterEncoding("UTF-8");
    }

    @Override
    public void destroy() {
        if (emf != null && emf.isOpen()) {
            emf.close();
        }
    }
}