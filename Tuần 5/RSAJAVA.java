import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class RSAGui extends JFrame {

    // ================= KHAI BÁO CÁC Ô NHẬP, Ô HIỂN THỊ =================
    private JTextField txtP;
    private JTextField txtQ;
    private JTextField txtE;
    private JTextField txtN;
    private JTextField txtPhi;
    private JTextField txtD;

    private JTextArea txtPublicKey;
    private JTextArea txtPrivateKey;

    private JTextArea txtPlainText;
    private JTextArea txtCipherText;

    private JTextArea txtCipherInput;
    private JTextArea txtDecryptedText;

    private JComboBox<String> cboMode;
    private JLabel lblStatus;

    // ================= KHAI BÁO BIẾN TOÁN HỌC RSA =================
    private BigInteger p, q, e, n, phi, d;

    // ================= LƯU BẢN RÕ VÀ BẢN MÃ GỐC SAU KHI MÃ HÓA =================
    private String lastPlainText = "";
    private String lastCipherText = "";

    // ================= BỘ SINH SỐ NGẪU NHIÊN =================
    private final SecureRandom random = new SecureRandom();

    // ================= ĐỘ DÀI BIT KHI TỰ SINH p, q =================
    // 32 bit: chạy nhanh, phù hợp demo báo cáo.
    // Có thể đổi thành 64 nếu muốn số lớn hơn.
    private static final int AUTO_PRIME_BIT_LENGTH = 32;

    // ================= HÀM KHỞI TẠO CHƯƠNG TRÌNH =================
    public RSAGui() {
        setTitle("Chương trình mã hóa và giải mã RSA");
        setSize(1220, 740);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(null);
        getContentPane().setBackground(new Color(210, 216, 220));

        initUI();
    }

    // ================= HÀM THIẾT KẾ GIAO DIỆN =================
    private void initUI() {
        JLabel lblTitle = new JLabel("CHƯƠNG TRÌNH MÃ HÓA VÀ GIẢI MÃ RSA", SwingConstants.CENTER);
        lblTitle.setFont(new Font("Arial", Font.BOLD, 18));
        lblTitle.setBounds(250, 10, 700, 30);
        add(lblTitle);

        // Nút thoát đặt riêng ở góc trên bên phải
        JButton btnExit = new JButton("Thoát");
        btnExit.setBounds(1080, 12, 90, 30);
        add(btnExit);

        // ================= KHỐI SINH KHÓA RSA =================
        JPanel keyPanel = new JPanel(null);
        keyPanel.setBackground(new Color(210, 216, 220));
        keyPanel.setBorder(BorderFactory.createTitledBorder("SINH KHÓA RSA"));
        keyPanel.setBounds(20, 55, 380, 610);
        add(keyPanel);

        JLabel lblP = new JLabel("Nhập p:");
        lblP.setFont(new Font("Arial", Font.BOLD, 12));
        lblP.setBounds(20, 35, 100, 25);
        keyPanel.add(lblP);

        txtP = new JTextField();
        txtP.setBounds(120, 35, 230, 25);
        keyPanel.add(txtP);

        JLabel lblQ = new JLabel("Nhập q:");
        lblQ.setFont(new Font("Arial", Font.BOLD, 12));
        lblQ.setBounds(20, 70, 100, 25);
        keyPanel.add(lblQ);

        txtQ = new JTextField();
        txtQ.setBounds(120, 70, 230, 25);
        keyPanel.add(txtQ);

        JLabel lblE = new JLabel("Nhập e:");
        lblE.setFont(new Font("Arial", Font.BOLD, 12));
        lblE.setBounds(20, 105, 100, 25);
        keyPanel.add(lblE);

        txtE = new JTextField();
        txtE.setBounds(120, 105, 230, 25);
        keyPanel.add(txtE);

        JLabel lblMode = new JLabel("Chế độ:");
        lblMode.setFont(new Font("Arial", Font.BOLD, 12));
        lblMode.setBounds(20, 140, 100, 25);
        keyPanel.add(lblMode);

        cboMode = new JComboBox<>(new String[]{"Số nguyên", "Văn bản"});
        cboMode.setBounds(120, 140, 230, 25);
        keyPanel.add(cboMode);

        JButton btnGenerateKey = new JButton("Sinh khóa RSA");
        btnGenerateKey.setBounds(30, 180, 145, 30);
        keyPanel.add(btnGenerateKey);

        JButton btnAutoGenerateKey = new JButton("Tự sinh khóa");
        btnAutoGenerateKey.setBounds(195, 180, 145, 30);
        keyPanel.add(btnAutoGenerateKey);

        JLabel lblN = new JLabel("n = p × q:");
        lblN.setFont(new Font("Arial", Font.BOLD, 12));
        lblN.setBounds(20, 230, 100, 25);
        keyPanel.add(lblN);

        txtN = new JTextField();
        txtN.setEditable(false);
        txtN.setBounds(120, 230, 230, 25);
        keyPanel.add(txtN);

        JLabel lblPhi = new JLabel("φ(n):");
        lblPhi.setFont(new Font("Arial", Font.BOLD, 12));
        lblPhi.setBounds(20, 265, 100, 25);
        keyPanel.add(lblPhi);

        txtPhi = new JTextField();
        txtPhi.setEditable(false);
        txtPhi.setBounds(120, 265, 230, 25);
        keyPanel.add(txtPhi);

        JLabel lblD = new JLabel("d:");
        lblD.setFont(new Font("Arial", Font.BOLD, 12));
        lblD.setBounds(20, 300, 100, 25);
        keyPanel.add(lblD);

        txtD = new JTextField();
        txtD.setEditable(false);
        txtD.setBounds(120, 300, 230, 25);
        keyPanel.add(txtD);

        JLabel lblPublicKey = new JLabel("Khóa công khai Kp = {e, n}:");
        lblPublicKey.setFont(new Font("Arial", Font.BOLD, 12));
        lblPublicKey.setBounds(20, 340, 230, 25);
        keyPanel.add(lblPublicKey);

        txtPublicKey = new JTextArea();
        txtPublicKey.setLineWrap(true);
        txtPublicKey.setWrapStyleWord(true);
        txtPublicKey.setEditable(false);
        JScrollPane scrollPublic = new JScrollPane(txtPublicKey);
        scrollPublic.setBounds(20, 370, 330, 80);
        keyPanel.add(scrollPublic);

        JLabel lblPrivateKey = new JLabel("Khóa bí mật Ks = {d, n}:");
        lblPrivateKey.setFont(new Font("Arial", Font.BOLD, 12));
        lblPrivateKey.setBounds(20, 465, 230, 25);
        keyPanel.add(lblPrivateKey);

        txtPrivateKey = new JTextArea();
        txtPrivateKey.setLineWrap(true);
        txtPrivateKey.setWrapStyleWord(true);
        txtPrivateKey.setEditable(false);
        JScrollPane scrollPrivate = new JScrollPane(txtPrivateKey);
        scrollPrivate.setBounds(20, 495, 330, 80);
        keyPanel.add(scrollPrivate);

        // ================= KHỐI MÃ HÓA =================
        JPanel encryptPanel = new JPanel(null);
        encryptPanel.setBackground(new Color(210, 216, 220));
        encryptPanel.setBorder(BorderFactory.createTitledBorder("MÃ HÓA THÔNG ĐIỆP"));
        encryptPanel.setBounds(420, 55, 350, 610);
        add(encryptPanel);

        JLabel lblPlain = new JLabel("Nhập bản rõ:");
        lblPlain.setFont(new Font("Arial", Font.BOLD, 12));
        lblPlain.setBounds(20, 35, 150, 25);
        encryptPanel.add(lblPlain);

        JButton btnLoadPlain = new JButton("Tải file bản rõ");
        btnLoadPlain.setBounds(190, 35, 140, 25);
        encryptPanel.add(btnLoadPlain);

        txtPlainText = new JTextArea();
        txtPlainText.setLineWrap(true);
        txtPlainText.setWrapStyleWord(true);
        JScrollPane scrollPlain = new JScrollPane(txtPlainText);
        scrollPlain.setBounds(20, 65, 310, 160);
        encryptPanel.add(scrollPlain);

        JButton btnEncrypt = new JButton("Mã hóa");
        btnEncrypt.setBounds(110, 245, 130, 30);
        encryptPanel.add(btnEncrypt);

        JLabel lblCipher = new JLabel("Bản mã:");
        lblCipher.setFont(new Font("Arial", Font.BOLD, 12));
        lblCipher.setBounds(20, 300, 150, 25);
        encryptPanel.add(lblCipher);

        txtCipherText = new JTextArea();
        txtCipherText.setLineWrap(true);
        txtCipherText.setWrapStyleWord(true);
        JScrollPane scrollCipher = new JScrollPane(txtCipherText);
        scrollCipher.setBounds(20, 330, 310, 180);
        encryptPanel.add(scrollCipher);

        JButton btnSaveCipher = new JButton("Lưu bản mã");
        btnSaveCipher.setBounds(20, 535, 140, 30);
        encryptPanel.add(btnSaveCipher);

        JButton btnClearEncrypt = new JButton("Xóa mã hóa");
        btnClearEncrypt.setBounds(190, 535, 140, 30);
        encryptPanel.add(btnClearEncrypt);

        // ================= KHỐI GIẢI MÃ =================
        JPanel decryptPanel = new JPanel(null);
        decryptPanel.setBackground(new Color(210, 216, 220));
        decryptPanel.setBorder(BorderFactory.createTitledBorder("GIẢI MÃ THÔNG ĐIỆP"));
        decryptPanel.setBounds(790, 55, 390, 610);
        add(decryptPanel);

        JLabel lblCipherInput = new JLabel("Nhập bản mã cần giải mã:");
        lblCipherInput.setFont(new Font("Arial", Font.BOLD, 12));
        lblCipherInput.setBounds(20, 35, 180, 25);
        decryptPanel.add(lblCipherInput);

        JButton btnLoadCipher = new JButton("Tải file bản mã");
        btnLoadCipher.setBounds(220, 35, 140, 25);
        decryptPanel.add(btnLoadCipher);

        txtCipherInput = new JTextArea();
        txtCipherInput.setLineWrap(true);
        txtCipherInput.setWrapStyleWord(true);
        JScrollPane scrollCipherInput = new JScrollPane(txtCipherInput);
        scrollCipherInput.setBounds(20, 65, 340, 160);
        decryptPanel.add(scrollCipherInput);

        JButton btnDecrypt = new JButton("Giải mã");
        btnDecrypt.setBounds(125, 245, 130, 30);
        decryptPanel.add(btnDecrypt);

        JLabel lblDecrypted = new JLabel("Bản rõ sau giải mã:");
        lblDecrypted.setFont(new Font("Arial", Font.BOLD, 12));
        lblDecrypted.setBounds(20, 300, 200, 25);
        decryptPanel.add(lblDecrypted);

        txtDecryptedText = new JTextArea();
        txtDecryptedText.setLineWrap(true);
        txtDecryptedText.setWrapStyleWord(true);
        JScrollPane scrollDecrypted = new JScrollPane(txtDecryptedText);
        scrollDecrypted.setBounds(20, 330, 340, 180);
        decryptPanel.add(scrollDecrypted);

        JButton btnSavePlain = new JButton("Lưu bản rõ");
        btnSavePlain.setBounds(60, 535, 120, 30);
        decryptPanel.add(btnSavePlain);

        JButton btnClearDecrypt = new JButton("Xóa giải mã");
        btnClearDecrypt.setBounds(210, 535, 120, 30);
        decryptPanel.add(btnClearDecrypt);

        // ================= NHÃN TRẠNG THÁI =================
        lblStatus = new JLabel("Trạng thái: Chưa thực hiện");
        lblStatus.setFont(new Font("Arial", Font.BOLD, 13));
        lblStatus.setBounds(20, 680, 1100, 25);
        add(lblStatus);

        // ================= GÁN SỰ KIỆN CHO CÁC NÚT =================
        btnGenerateKey.addActionListener(this::generateKeyAction);
        btnAutoGenerateKey.addActionListener(this::autoGenerateKeyAction);

        btnEncrypt.addActionListener(this::encryptAction);
        btnDecrypt.addActionListener(this::decryptAction);

        btnLoadPlain.addActionListener(e -> loadFileToTextArea(txtPlainText));
        btnLoadCipher.addActionListener(e -> loadFileToTextArea(txtCipherInput));

        btnSaveCipher.addActionListener(e -> saveTextAreaToFile(txtCipherText, "ban_ma.txt"));
        btnSavePlain.addActionListener(e -> saveTextAreaToFile(txtDecryptedText, "ban_ro_giai_ma.txt"));

        btnClearEncrypt.addActionListener(e -> clearEncryptArea());
        btnClearDecrypt.addActionListener(e -> clearDecryptArea());
        btnExit.addActionListener(e -> exitProgram());
    }

    // ================= HÀM KIỂM TRA SỐ NGUYÊN TỐ =================
    private boolean isPrime(BigInteger number) {
        if (number.compareTo(BigInteger.valueOf(2)) < 0) {
            return false;
        }

        if (number.equals(BigInteger.valueOf(2))) {
            return true;
        }

        if (number.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            return false;
        }

        // Với số lớn, dùng kiểm tra xác suất nguyên tố để chương trình chạy nhanh
        if (number.bitLength() > 24) {
            return number.isProbablePrime(40);
        }

        BigInteger i = BigInteger.valueOf(3);

        while (i.multiply(i).compareTo(number) <= 0) {
            if (number.mod(i).equals(BigInteger.ZERO)) {
                return false;
            }

            i = i.add(BigInteger.valueOf(2));
        }

        return true;
    }

    // ================= HÀM GCD - THUẬT TOÁN EUCLID =================
    private BigInteger gcd(BigInteger a, BigInteger b) {
        a = a.abs();
        b = b.abs();

        while (!b.equals(BigInteger.ZERO)) {
            BigInteger r = a.mod(b);
            a = b;
            b = r;
        }

        return a;
    }

    // ================= HÀM EUCLID MỞ RỘNG =================
    private BigInteger[] extendedEuclid(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }

        BigInteger[] result = extendedEuclid(b, a.mod(b));

        BigInteger gcd = result[0];
        BigInteger x1 = result[1];
        BigInteger y1 = result[2];

        BigInteger x = y1;
        BigInteger y = x1.subtract(a.divide(b).multiply(y1));

        return new BigInteger[]{gcd, x, y};
    }

    // ================= HÀM TÌM NGHỊCH ĐẢO MODULO =================
    private BigInteger modInverse(BigInteger a, BigInteger mod) {
        BigInteger[] result = extendedEuclid(a, mod);

        BigInteger gcd = result[0];
        BigInteger x = result[1];

        if (!gcd.equals(BigInteger.ONE)) {
            throw new ArithmeticException("Không tồn tại nghịch đảo modulo!");
        }

        return x.mod(mod);
    }

    // ================= HÀM LŨY THỪA MODULO =================
    private BigInteger modularPower(BigInteger base, BigInteger exponent, BigInteger mod) {
        BigInteger result = BigInteger.ONE;

        base = base.mod(mod);

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            if (exponent.mod(BigInteger.valueOf(2)).equals(BigInteger.ONE)) {
                result = result.multiply(base).mod(mod);
            }

            base = base.multiply(base).mod(mod);
            exponent = exponent.divide(BigInteger.valueOf(2));
        }

        return result;
    }

    // ================= HÀM SINH SỐ NGUYÊN TỐ NGẪU NHIÊN =================
    private BigInteger generatePrime(int bitLength) {
        while (true) {
            BigInteger candidate = new BigInteger(bitLength, random);

            // Đảm bảo số có đúng độ dài bit
            candidate = candidate.setBit(bitLength - 1);

            // Đảm bảo số lẻ
            candidate = candidate.setBit(0);

            if (isPrime(candidate)) {
                return candidate;
            }
        }
    }

    // ================= HÀM TỰ ĐỘNG CHỌN e =================
    private BigInteger generateE(BigInteger phiValue) {
        // Ưu tiên dùng e = 65537 vì đây là giá trị phổ biến trong RSA
        BigInteger commonE = BigInteger.valueOf(65537);

        if (commonE.compareTo(BigInteger.ONE) > 0 &&
                commonE.compareTo(phiValue) < 0 &&
                gcd(commonE, phiValue).equals(BigInteger.ONE)) {
            return commonE;
        }

        // Nếu 65537 không phù hợp thì tự sinh e khác
        while (true) {
            BigInteger candidate = new BigInteger(phiValue.bitLength() - 1, random);

            candidate = candidate.setBit(0);

            if (candidate.compareTo(BigInteger.ONE) > 0 &&
                    candidate.compareTo(phiValue) < 0 &&
                    gcd(candidate, phiValue).equals(BigInteger.ONE)) {
                return candidate;
            }
        }
    }

    // ================= HÀM TỰ ĐỘNG SINH KHÓA RSA =================
    private void autoGenerateKeyAction(ActionEvent event) {
        try {
            // 32 bit giúp chạy nhanh, đủ để demo chữ và số
            int bitLength = 32;

            // Sinh p, q là 2 số nguyên tố khác nhau
            p = generatePrime(bitLength);

            do {
                q = generatePrime(bitLength);
            } while (p.equals(q));

            // Tính n = p * q
            n = p.multiply(q);

            // Tính phi(n) = (p - 1) * (q - 1)
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            // Tự chọn e sao cho gcd(e, phi(n)) = 1
            e = generateE(phi);

            // Tính d = e^(-1) mod phi(n)
            d = modInverse(e, phi);

            // Hiển thị lên giao diện
            txtP.setText(p.toString());
            txtQ.setText(q.toString());
            txtE.setText(e.toString());

            txtN.setText(n.toString());
            txtPhi.setText(phi.toString());
            txtD.setText(d.toString());

            txtPublicKey.setText("Kp = {" + e + ", " + n + "}");
            txtPrivateKey.setText("Ks = {" + d + ", " + n + "}");

            lastPlainText = "";
            lastCipherText = "";

            lblStatus.setText("Trạng thái: Tự động sinh khóa thành công");

            JOptionPane.showMessageDialog(this, "Tự động sinh khóa RSA thành công!");

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Lỗi tự động sinh khóa: " + ex.getMessage());
        }
    }

    // ================= HÀM SINH KHÓA RSA THỦ CÔNG =================
    private void generateKeyAction(ActionEvent event) {
        try {
            String pText = txtP.getText().trim();
            String qText = txtQ.getText().trim();
            String eText = txtE.getText().trim();

            if (pText.isEmpty() || qText.isEmpty() || eText.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Vui lòng nhập đầy đủ p, q và e!");
                return;
            }

            p = new BigInteger(pText);
            q = new BigInteger(qText);
            e = new BigInteger(eText);

            if (!isPrime(p)) {
                JOptionPane.showMessageDialog(this, "p không phải là số nguyên tố!");
                return;
            }

            if (!isPrime(q)) {
                JOptionPane.showMessageDialog(this, "q không phải là số nguyên tố!");
                return;
            }

            if (p.equals(q)) {
                JOptionPane.showMessageDialog(this, "p và q phải là hai số nguyên tố khác nhau!");
                return;
            }

            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            if (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0) {
                JOptionPane.showMessageDialog(this, "e phải thỏa mãn: 1 < e < φ(n)!");
                return;
            }

            if (!gcd(e, phi).equals(BigInteger.ONE)) {
                JOptionPane.showMessageDialog(this, "e phải nguyên tố cùng nhau với φ(n), tức gcd(e, φ(n)) = 1!");
                return;
            }

            d = modInverse(e, phi);

            txtN.setText(n.toString());
            txtPhi.setText(phi.toString());
            txtD.setText(d.toString());

            txtPublicKey.setText("Kp = {" + e + ", " + n + "}");
            txtPrivateKey.setText("Ks = {" + d + ", " + n + "}");

            lastPlainText = "";
            lastCipherText = "";

            lblStatus.setText("Trạng thái: Sinh khóa thành công");

            JOptionPane.showMessageDialog(this, "Sinh khóa RSA thành công!");

        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "p, q và e phải là số nguyên hợp lệ!");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Lỗi sinh khóa: " + ex.getMessage());
        }
    }

    // ================= HÀM MÃ HÓA THÔNG ĐIỆP =================
    private void encryptAction(ActionEvent event) {
        try {
            if (!isKeyGenerated()) {
                JOptionPane.showMessageDialog(this, "Bạn cần sinh khóa RSA trước!");
                return;
            }

            String mode = cboMode.getSelectedItem().toString();

            if (mode.equals("Số nguyên")) {
                encryptNumber();
            } else {
                encryptText();
            }

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Lỗi mã hóa: " + ex.getMessage());
        }
    }

    // ================= HÀM MÃ HÓA SỐ NGUYÊN =================
    private void encryptNumber() {
        String plainText = txtPlainText.getText().trim();

        if (plainText.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Vui lòng nhập bản rõ M cần mã hóa!");
            return;
        }

        try {
            BigInteger m = new BigInteger(plainText);

            if (m.compareTo(BigInteger.ZERO) <= 0 || m.compareTo(n) >= 0) {
                JOptionPane.showMessageDialog(this, "M phải thỏa mãn: 0 < M < n!");
                return;
            }

            BigInteger c = modularPower(m, e, n);

            txtCipherText.setText(c.toString());

            lastPlainText = m.toString();
            lastCipherText = c.toString();

            lblStatus.setText("Trạng thái: Mã hóa số nguyên thành công. C = " + c);

            JOptionPane.showMessageDialog(this, "Mã hóa số nguyên thành công!");

        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Ở chế độ Số nguyên, bản rõ M phải là số nguyên!");
        }
    }

    // ================= HÀM MÃ HÓA VĂN BẢN =================
    private void encryptText() {
        String plainText = txtPlainText.getText();

        if (plainText.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Vui lòng nhập văn bản cần mã hóa!");
            return;
        }

        if (n.compareTo(BigInteger.valueOf(255)) <= 0) {
            JOptionPane.showMessageDialog(
                    this,
                    "n = p × q phải lớn hơn 255 để mã hóa văn bản!\n" +
                            "Bạn hãy chọn p, q lớn hơn.\n\n" +
                            "Ví dụ:\n" +
                            "p = 61, q = 53, e = 17"
            );
            return;
        }

        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        List<String> cipherBlocks = new ArrayList<>();

        for (byte b : plainBytes) {
            int unsignedByte = b & 0xFF;

            BigInteger m = BigInteger.valueOf(unsignedByte);

            BigInteger c = modularPower(m, e, n);

            cipherBlocks.add(c.toString());
        }

        String cipherText = String.join(" ", cipherBlocks);

        txtCipherText.setText(cipherText);

        lastPlainText = plainText;
        lastCipherText = cipherText;

        lblStatus.setText("Trạng thái: Mã hóa văn bản thành công. Có thể copy bản mã sang phần giải mã.");

        JOptionPane.showMessageDialog(this, "Mã hóa văn bản thành công!");
    }

    // ================= HÀM GIẢI MÃ THÔNG ĐIỆP =================
    private void decryptAction(ActionEvent event) {
        try {
            if (!isKeyGenerated()) {
                JOptionPane.showMessageDialog(this, "Bạn cần sinh khóa RSA trước!");
                return;
            }

            String cipherInput = txtCipherInput.getText().trim();

            if (cipherInput.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Vui lòng nhập bản mã cần giải mã!");
                return;
            }

            if (!lastCipherText.trim().isEmpty()) {
                String normalizedInput = normalizeCipherText(cipherInput);
                String normalizedOriginal = normalizeCipherText(lastCipherText);

                if (!normalizedInput.equals(normalizedOriginal)) {
                    int confirm = JOptionPane.showConfirmDialog(
                            this,
                            "Bản mã nhập vào đã bị thay đổi so với bản mã được tạo ở phần mã hóa.\n" +
                                    "Bạn có muốn tiếp tục giải mã bản mã đã bị thay đổi không?",
                            "Cảnh báo bản mã bị thay đổi",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE
                    );

                    lblStatus.setText("Cảnh báo: Bản mã nhập vào đã bị thay đổi so với bản mã được tạo ở phần mã hóa.");

                    if (confirm != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
            }

            String mode = cboMode.getSelectedItem().toString();

            if (mode.equals("Số nguyên")) {
                decryptNumber();
            } else {
                decryptText();
            }

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Lỗi giải mã: " + ex.getMessage());
        }
    }

    // ================= HÀM GIẢI MÃ SỐ NGUYÊN =================
    private void decryptNumber() {
        String cipherInput = txtCipherInput.getText().trim();

        try {
            BigInteger c = new BigInteger(cipherInput);

            if (c.compareTo(BigInteger.ZERO) < 0 || c.compareTo(n) >= 0) {
                JOptionPane.showMessageDialog(this, "C phải thỏa mãn: 0 ≤ C < n!");
                return;
            }

            BigInteger m = modularPower(c, d, n);

            txtDecryptedText.setText(m.toString());

            if (!lastPlainText.isEmpty() && m.toString().equals(lastPlainText)) {
                lblStatus.setText("Trạng thái: Giải mã số nguyên thành công. Bản rõ trùng với bản rõ ban đầu.");
            } else {
                lblStatus.setText("Trạng thái: Giải mã số nguyên xong. Bản rõ sau giải mã có thể đã khác bản rõ ban đầu.");
            }

            JOptionPane.showMessageDialog(this, "Giải mã số nguyên thành công!");

        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Ở chế độ Số nguyên, bản mã C phải là số nguyên!");
        }
    }

    // ================= HÀM GIẢI MÃ VĂN BẢN =================
    private void decryptText() {
        String cipherInput = txtCipherInput.getText().trim();

        try {
            String[] blocks = cipherInput.split("\\s+");

            byte[] decryptedBytes = new byte[blocks.length];

            for (int i = 0; i < blocks.length; i++) {
                BigInteger c = new BigInteger(blocks[i]);

                if (c.compareTo(BigInteger.ZERO) < 0 || c.compareTo(n) >= 0) {
                    JOptionPane.showMessageDialog(this, "Bản mã C phải thỏa mãn: 0 ≤ C < n!");
                    return;
                }

                BigInteger m = modularPower(c, d, n);

                int originalByte = m.intValue();

                if (originalByte < 0 || originalByte > 255) {
                    JOptionPane.showMessageDialog(
                            this,
                            "Giải mã lỗi! Có thể bạn nhập sai bản mã hoặc dùng sai khóa."
                    );
                    return;
                }

                decryptedBytes[i] = (byte) originalByte;
            }

            String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

            txtDecryptedText.setText(decryptedText);

            if (!lastPlainText.isEmpty() && decryptedText.equals(lastPlainText)) {
                lblStatus.setText("Trạng thái: Giải mã văn bản thành công. Bản rõ trùng với bản rõ ban đầu.");
            } else {
                lblStatus.setText("Trạng thái: Giải mã văn bản xong. Bản rõ sau giải mã có thể đã khác bản rõ ban đầu.");
            }

            JOptionPane.showMessageDialog(this, "Giải mã văn bản thành công!");

        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Ở chế độ Văn bản, bản mã chỉ được chứa các số cách nhau bằng dấu cách!");
        }
    }

    // ================= HÀM CHUẨN HÓA BẢN MÃ ĐỂ SO SÁNH =================
    private String normalizeCipherText(String text) {
        return text.trim().replaceAll("\\s+", " ");
    }

    // ================= HÀM TẢI FILE VÀO TEXTAREA =================
    private void loadFileToTextArea(JTextArea textArea) {
        try {
            JFileChooser fileChooser = new JFileChooser();

            int result = fileChooser.showOpenDialog(this);

            if (result == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();

                String content = new String(
                        Files.readAllBytes(file.toPath()),
                        StandardCharsets.UTF_8
                );

                textArea.setText(content);

                lblStatus.setText("Trạng thái: Đã tải file " + file.getName());
            }

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Lỗi tải file: " + ex.getMessage());
        }
    }

    // ================= HÀM LƯU TEXTAREA RA FILE =================
    private void saveTextAreaToFile(JTextArea textArea, String defaultFileName) {
        try {
            if (textArea.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "Không có nội dung để lưu!");
                return;
            }

            JFileChooser fileChooser = new JFileChooser();

            fileChooser.setSelectedFile(new File(defaultFileName));

            int result = fileChooser.showSaveDialog(this);

            if (result == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();

                Files.write(
                        file.toPath(),
                        textArea.getText().getBytes(StandardCharsets.UTF_8)
                );

                lblStatus.setText("Trạng thái: Đã lưu file " + file.getName());

                JOptionPane.showMessageDialog(this, "Lưu file thành công!");
            }

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Lỗi lưu file: " + ex.getMessage());
        }
    }

    // ================= HÀM XÓA PHẦN MÃ HÓA =================
    private void clearEncryptArea() {
        txtPlainText.setText("");
        txtCipherText.setText("");

        lastPlainText = "";
        lastCipherText = "";

        lblStatus.setText("Trạng thái: Đã xóa phần mã hóa");
    }

    // ================= HÀM XÓA PHẦN GIẢI MÃ =================
    private void clearDecryptArea() {
        txtCipherInput.setText("");
        txtDecryptedText.setText("");

        lblStatus.setText("Trạng thái: Đã xóa phần giải mã");
    }

    // ================= HÀM THOÁT CHƯƠNG TRÌNH =================
    private void exitProgram() {
        int confirm = JOptionPane.showConfirmDialog(
                this,
                "Bạn có chắc chắn muốn thoát chương trình không?",
                "Xác nhận thoát",
                JOptionPane.YES_NO_OPTION
        );

        if (confirm == JOptionPane.YES_OPTION) {
            System.exit(0);
        }
    }

    // ================= HÀM KIỂM TRA ĐÃ SINH KHÓA CHƯA =================
    private boolean isKeyGenerated() {
        return p != null && q != null && e != null && n != null && phi != null && d != null;
    }

    // ================= HÀM MAIN CHẠY CHƯƠNG TRÌNH =================
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            RSAGui app = new RSAGui();
            app.setVisible(true);
        });
    }
}