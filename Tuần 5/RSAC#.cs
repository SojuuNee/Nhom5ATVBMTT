using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

public class RSAGui : Form
{
    // ================= KHAI BÁO CÁC Ô NHẬP, Ô HIỂN THỊ =================
    private TextBox txtP;
    private TextBox txtQ;
    private TextBox txtE;
    private TextBox txtN;
    private TextBox txtPhi;
    private TextBox txtD;

    private TextBox txtPublicKey;
    private TextBox txtPrivateKey;

    private TextBox txtPlainText;
    private TextBox txtCipherText;

    private TextBox txtCipherInput;
    private TextBox txtDecryptedText;

    private ComboBox cboMode;
    private Label lblStatus;

    // ================= KHAI BÁO BIẾN TOÁN HỌC RSA =================
    private BigInteger p;
    private BigInteger q;
    private BigInteger eValue;
    private BigInteger n;
    private BigInteger phi;
    private BigInteger d;

    // ================= KIỂM TRA ĐÃ CÓ KHÓA CHƯA =================
    private bool hasKey = false;

    // ================= LƯU BẢN RÕ VÀ BẢN MÃ GỐC SAU KHI MÃ HÓA =================
    private string lastPlainText = "";
    private string lastCipherText = "";

    // ================= ĐỘ DÀI BIT KHI TỰ SINH p, q =================
    // 32 bit: chạy nhanh, phù hợp demo báo cáo.
    // Có thể đổi thành 64 nếu muốn số lớn hơn.
    private const int AUTO_PRIME_BIT_LENGTH = 32;

    // ================= HÀM KHỞI TẠO CHƯƠNG TRÌNH =================
    public RSAGui()
    {
        Text = "Chương trình mã hóa và giải mã RSA";
        Size = new Size(1220, 760);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        BackColor = Color.FromArgb(210, 216, 220);

        InitUI();
    }

    // ================= HÀM THIẾT KẾ GIAO DIỆN =================
    private void InitUI()
    {
        Label lblTitle = new Label();
        lblTitle.Text = "CHƯƠNG TRÌNH MÃ HÓA VÀ GIẢI MÃ RSA";
        lblTitle.Font = new Font("Arial", 14, FontStyle.Bold);
        lblTitle.TextAlign = ContentAlignment.MiddleCenter;
        lblTitle.SetBounds(250, 10, 700, 30);
        Controls.Add(lblTitle);

        Button btnExit = new Button();
        btnExit.Text = "Thoát";
        btnExit.SetBounds(1080, 12, 90, 30);
        btnExit.Click += (sender, args) => ExitProgram();
        Controls.Add(btnExit);

        // ================= KHỐI SINH KHÓA RSA =================
        GroupBox keyPanel = new GroupBox();
        keyPanel.Text = "SINH KHÓA RSA";
        keyPanel.SetBounds(20, 55, 380, 610);
        keyPanel.BackColor = Color.FromArgb(210, 216, 220);
        Controls.Add(keyPanel);

        keyPanel.Controls.Add(CreateLabel("Nhập p:", 20, 35, 100, 25));
        txtP = CreateSingleTextBox(120, 35, 230, 25);
        keyPanel.Controls.Add(txtP);

        keyPanel.Controls.Add(CreateLabel("Nhập q:", 20, 70, 100, 25));
        txtQ = CreateSingleTextBox(120, 70, 230, 25);
        keyPanel.Controls.Add(txtQ);

        keyPanel.Controls.Add(CreateLabel("Nhập e:", 20, 105, 100, 25));
        txtE = CreateSingleTextBox(120, 105, 230, 25);
        keyPanel.Controls.Add(txtE);

        keyPanel.Controls.Add(CreateLabel("Chế độ:", 20, 140, 100, 25));
        cboMode = new ComboBox();
        cboMode.Items.Add("Số nguyên");
        cboMode.Items.Add("Văn bản");
        cboMode.SelectedIndex = 0;
        cboMode.DropDownStyle = ComboBoxStyle.DropDownList;
        cboMode.SetBounds(120, 140, 230, 25);
        keyPanel.Controls.Add(cboMode);

        Button btnGenerateKey = new Button();
        btnGenerateKey.Text = "Sinh khóa RSA";
        btnGenerateKey.SetBounds(30, 180, 145, 30);
        btnGenerateKey.Click += GenerateKeyAction;
        keyPanel.Controls.Add(btnGenerateKey);

        Button btnAutoGenerateKey = new Button();
        btnAutoGenerateKey.Text = "Tự sinh khóa";
        btnAutoGenerateKey.SetBounds(195, 180, 145, 30);
        btnAutoGenerateKey.Click += AutoGenerateKeyAction;
        keyPanel.Controls.Add(btnAutoGenerateKey);

        keyPanel.Controls.Add(CreateLabel("n = p × q:", 20, 230, 100, 25));
        txtN = CreateSingleTextBox(120, 230, 230, 25);
        txtN.ReadOnly = true;
        keyPanel.Controls.Add(txtN);

        keyPanel.Controls.Add(CreateLabel("φ(n):", 20, 265, 100, 25));
        txtPhi = CreateSingleTextBox(120, 265, 230, 25);
        txtPhi.ReadOnly = true;
        keyPanel.Controls.Add(txtPhi);

        keyPanel.Controls.Add(CreateLabel("d:", 20, 300, 100, 25));
        txtD = CreateSingleTextBox(120, 300, 230, 25);
        txtD.ReadOnly = true;
        keyPanel.Controls.Add(txtD);

        keyPanel.Controls.Add(CreateLabel("Khóa công khai Kp = {e, n}:", 20, 340, 230, 25));
        txtPublicKey = CreateMultiTextBox(20, 370, 330, 80);
        txtPublicKey.ReadOnly = true;
        keyPanel.Controls.Add(txtPublicKey);

        keyPanel.Controls.Add(CreateLabel("Khóa bí mật Ks = {d, n}:", 20, 465, 230, 25));
        txtPrivateKey = CreateMultiTextBox(20, 495, 330, 80);
        txtPrivateKey.ReadOnly = true;
        keyPanel.Controls.Add(txtPrivateKey);

        // ================= KHỐI MÃ HÓA =================
        GroupBox encryptPanel = new GroupBox();
        encryptPanel.Text = "MÃ HÓA THÔNG ĐIỆP";
        encryptPanel.SetBounds(420, 55, 350, 610);
        encryptPanel.BackColor = Color.FromArgb(210, 216, 220);
        Controls.Add(encryptPanel);

        encryptPanel.Controls.Add(CreateLabel("Nhập bản rõ:", 20, 35, 150, 25));

        Button btnLoadPlain = new Button();
        btnLoadPlain.Text = "Tải file bản rõ";
        btnLoadPlain.SetBounds(190, 35, 140, 25);
        btnLoadPlain.Click += (sender, args) => LoadFileToTextBox(txtPlainText);
        encryptPanel.Controls.Add(btnLoadPlain);

        txtPlainText = CreateMultiTextBox(20, 65, 310, 160);
        encryptPanel.Controls.Add(txtPlainText);

        Button btnEncrypt = new Button();
        btnEncrypt.Text = "Mã hóa";
        btnEncrypt.SetBounds(110, 245, 130, 30);
        btnEncrypt.Click += EncryptAction;
        encryptPanel.Controls.Add(btnEncrypt);

        encryptPanel.Controls.Add(CreateLabel("Bản mã:", 20, 300, 150, 25));

        txtCipherText = CreateMultiTextBox(20, 330, 310, 180);
        encryptPanel.Controls.Add(txtCipherText);

        Button btnSaveCipher = new Button();
        btnSaveCipher.Text = "Lưu bản mã";
        btnSaveCipher.SetBounds(20, 535, 140, 30);
        btnSaveCipher.Click += (sender, args) => SaveTextBoxToFile(txtCipherText, "ban_ma.txt");
        encryptPanel.Controls.Add(btnSaveCipher);

        Button btnClearEncrypt = new Button();
        btnClearEncrypt.Text = "Xóa mã hóa";
        btnClearEncrypt.SetBounds(190, 535, 140, 30);
        btnClearEncrypt.Click += (sender, args) => ClearEncryptArea();
        encryptPanel.Controls.Add(btnClearEncrypt);

        // ================= KHỐI GIẢI MÃ =================
        GroupBox decryptPanel = new GroupBox();
        decryptPanel.Text = "GIẢI MÃ THÔNG ĐIỆP";
        decryptPanel.SetBounds(790, 55, 390, 610);
        decryptPanel.BackColor = Color.FromArgb(210, 216, 220);
        Controls.Add(decryptPanel);

        decryptPanel.Controls.Add(CreateLabel("Nhập bản mã cần giải mã:", 20, 35, 180, 25));

        Button btnLoadCipher = new Button();
        btnLoadCipher.Text = "Tải file bản mã";
        btnLoadCipher.SetBounds(220, 35, 140, 25);
        btnLoadCipher.Click += (sender, args) => LoadFileToTextBox(txtCipherInput);
        decryptPanel.Controls.Add(btnLoadCipher);

        txtCipherInput = CreateMultiTextBox(20, 65, 340, 160);
        decryptPanel.Controls.Add(txtCipherInput);

        Button btnDecrypt = new Button();
        btnDecrypt.Text = "Giải mã";
        btnDecrypt.SetBounds(125, 245, 130, 30);
        btnDecrypt.Click += DecryptAction;
        decryptPanel.Controls.Add(btnDecrypt);

        decryptPanel.Controls.Add(CreateLabel("Bản rõ sau giải mã:", 20, 300, 200, 25));

        txtDecryptedText = CreateMultiTextBox(20, 330, 340, 180);
        decryptPanel.Controls.Add(txtDecryptedText);

        Button btnSavePlain = new Button();
        btnSavePlain.Text = "Lưu bản rõ";
        btnSavePlain.SetBounds(60, 535, 120, 30);
        btnSavePlain.Click += (sender, args) => SaveTextBoxToFile(txtDecryptedText, "ban_ro_giai_ma.txt");
        decryptPanel.Controls.Add(btnSavePlain);

        Button btnClearDecrypt = new Button();
        btnClearDecrypt.Text = "Xóa giải mã";
        btnClearDecrypt.SetBounds(210, 535, 120, 30);
        btnClearDecrypt.Click += (sender, args) => ClearDecryptArea();
        decryptPanel.Controls.Add(btnClearDecrypt);

        // ================= NHÃN TRẠNG THÁI =================
        lblStatus = new Label();
        lblStatus.Text = "Trạng thái: Chưa thực hiện";
        lblStatus.Font = new Font("Arial", 10, FontStyle.Bold);
        lblStatus.SetBounds(20, 680, 1100, 25);
        Controls.Add(lblStatus);
    }

    // ================= HÀM TẠO LABEL =================
    private Label CreateLabel(string text, int x, int y, int width, int height)
    {
        Label label = new Label();
        label.Text = text;
        label.Font = new Font("Arial", 9, FontStyle.Bold);
        label.SetBounds(x, y, width, height);
        return label;
    }

    // ================= HÀM TẠO TEXTBOX 1 DÒNG =================
    private TextBox CreateSingleTextBox(int x, int y, int width, int height)
    {
        TextBox textBox = new TextBox();
        textBox.SetBounds(x, y, width, height);
        return textBox;
    }

    // ================= HÀM TẠO TEXTBOX NHIỀU DÒNG =================
    private TextBox CreateMultiTextBox(int x, int y, int width, int height)
    {
        TextBox textBox = new TextBox();
        textBox.Multiline = true;
        textBox.ScrollBars = ScrollBars.Vertical;
        textBox.WordWrap = true;
        textBox.SetBounds(x, y, width, height);
        return textBox;
    }

    // ================= HÀM KIỂM TRA SỐ NGUYÊN TỐ =================
    private bool IsPrime(BigInteger number)
    {
        if (number < 2)
        {
            return false;
        }

        if (number == 2)
        {
            return true;
        }

        if (number % 2 == 0)
        {
            return false;
        }

        // Với số lớn, dùng Miller-Rabin để kiểm tra nhanh
        if (number > 1000000)
        {
            return MillerRabin(number, 20);
        }

        BigInteger i = 3;

        while (i * i <= number)
        {
            if (number % i == 0)
            {
                return false;
            }

            i += 2;
        }

        return true;
    }

    // ================= HÀM MILLER-RABIN KIỂM TRA NGUYÊN TỐ =================
    private bool MillerRabin(BigInteger number, int rounds)
    {
        if (number < 2)
        {
            return false;
        }

        if (number == 2 || number == 3)
        {
            return true;
        }

        if (number % 2 == 0)
        {
            return false;
        }

        BigInteger dValue = number - 1;
        int s = 0;

        while (dValue % 2 == 0)
        {
            dValue /= 2;
            s++;
        }

        for (int i = 0; i < rounds; i++)
        {
            BigInteger a = RandomBigIntegerBetween(2, number - 2);

            BigInteger x = ModularPower(a, dValue, number);

            if (x == 1 || x == number - 1)
            {
                continue;
            }

            bool passed = false;

            for (int r = 1; r < s; r++)
            {
                x = (x * x) % number;

                if (x == number - 1)
                {
                    passed = true;
                    break;
                }
            }

            if (!passed)
            {
                return false;
            }
        }

        return true;
    }

    // ================= HÀM GCD - THUẬT TOÁN EUCLID =================
    private BigInteger Gcd(BigInteger a, BigInteger b)
    {
        a = BigInteger.Abs(a);
        b = BigInteger.Abs(b);

        while (b != 0)
        {
            BigInteger r = a % b;
            a = b;
            b = r;
        }

        return a;
    }

    // ================= HÀM EUCLID MỞ RỘNG =================
    private BigInteger[] ExtendedEuclid(BigInteger a, BigInteger b)
    {
        if (b == 0)
        {
            return new BigInteger[] { a, 1, 0 };
        }

        BigInteger[] result = ExtendedEuclid(b, a % b);

        BigInteger gcd = result[0];
        BigInteger x1 = result[1];
        BigInteger y1 = result[2];

        BigInteger x = y1;
        BigInteger y = x1 - (a / b) * y1;

        return new BigInteger[] { gcd, x, y };
    }

    // ================= HÀM TÌM NGHỊCH ĐẢO MODULO =================
    private BigInteger ModInverse(BigInteger a, BigInteger mod)
    {
        BigInteger[] result = ExtendedEuclid(a, mod);

        BigInteger gcd = result[0];
        BigInteger x = result[1];

        if (gcd != 1)
        {
            throw new Exception("Không tồn tại nghịch đảo modulo!");
        }

        return (x % mod + mod) % mod;
    }

    // ================= HÀM LŨY THỪA MODULO =================
    private BigInteger ModularPower(BigInteger baseValue, BigInteger exponent, BigInteger mod)
    {
        BigInteger result = 1;

        baseValue %= mod;

        while (exponent > 0)
        {
            if (exponent % 2 == 1)
            {
                result = (result * baseValue) % mod;
            }

            baseValue = (baseValue * baseValue) % mod;
            exponent /= 2;
        }

        return result;
    }

    // ================= HÀM SINH SỐ NGUYÊN TỐ NGẪU NHIÊN =================
    private BigInteger GeneratePrime(int bitLength)
    {
        while (true)
        {
            BigInteger candidate = GenerateRandomOddBigInteger(bitLength);

            if (IsPrime(candidate))
            {
                return candidate;
            }
        }
    }

    // ================= HÀM SINH SỐ NGUYÊN LẺ NGẪU NHIÊN THEO SỐ BIT =================
    private BigInteger GenerateRandomOddBigInteger(int bitLength)
    {
        int byteLength = (bitLength + 7) / 8;
        byte[] bytes = new byte[byteLength];

        RandomNumberGenerator.Fill(bytes);

        int excessBits = byteLength * 8 - bitLength;

        bytes[0] = (byte)(bytes[0] & (0xFF >> excessBits));
        bytes[0] = (byte)(bytes[0] | (1 << (7 - excessBits)));

        bytes[byteLength - 1] = (byte)(bytes[byteLength - 1] | 1);

        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }

    // ================= HÀM SINH SỐ NGẪU NHIÊN TRONG KHOẢNG [min, max] =================
    private BigInteger RandomBigIntegerBetween(BigInteger min, BigInteger max)
    {
        BigInteger range = max - min + 1;

        BigInteger result = RandomBigIntegerBelow(range);

        return result + min;
    }

    // ================= HÀM SINH SỐ NGẪU NHIÊN NHỎ HƠN max =================
    private BigInteger RandomBigIntegerBelow(BigInteger max)
    {
        if (max <= 0)
        {
            throw new ArgumentException("max phải lớn hơn 0");
        }

        byte[] bytes = max.ToByteArray(isUnsigned: true, isBigEndian: true);

        BigInteger result;

        do
        {
            RandomNumberGenerator.Fill(bytes);
            result = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        } while (result >= max);

        return result;
    }

    // ================= HÀM TỰ ĐỘNG CHỌN e =================
    private BigInteger GenerateE(BigInteger phiValue)
    {
        BigInteger commonE = 65537;

        if (commonE > 1 && commonE < phiValue && Gcd(commonE, phiValue) == 1)
        {
            return commonE;
        }

        while (true)
        {
            BigInteger candidate = RandomBigIntegerBetween(3, phiValue - 1);

            if (candidate % 2 == 0)
            {
                candidate += 1;
            }

            if (candidate > 1 && candidate < phiValue && Gcd(candidate, phiValue) == 1)
            {
                return candidate;
            }
        }
    }

    // ================= HÀM TỰ ĐỘNG SINH KHÓA RSA =================
    private void AutoGenerateKeyAction(object sender, EventArgs args)
    {
        try
        {
            int bitLength = AUTO_PRIME_BIT_LENGTH;

            p = GeneratePrime(bitLength);

            do
            {
                q = GeneratePrime(bitLength);
            } while (p == q);

            n = p * q;

            phi = (p - 1) * (q - 1);

            eValue = GenerateE(phi);

            d = ModInverse(eValue, phi);

            hasKey = true;

            txtP.Text = p.ToString();
            txtQ.Text = q.ToString();
            txtE.Text = eValue.ToString();

            txtN.Text = n.ToString();
            txtPhi.Text = phi.ToString();
            txtD.Text = d.ToString();

            txtPublicKey.Text = "Kp = {" + eValue + ", " + n + "}";
            txtPrivateKey.Text = "Ks = {" + d + ", " + n + "}";

            lastPlainText = "";
            lastCipherText = "";

            lblStatus.Text = "Trạng thái: Tự động sinh khóa thành công";

            MessageBox.Show("Tự động sinh khóa RSA thành công!");
        }
        catch (Exception ex)
        {
            MessageBox.Show("Lỗi tự động sinh khóa: " + ex.Message);
        }
    }

    // ================= HÀM SINH KHÓA RSA THỦ CÔNG =================
    private void GenerateKeyAction(object sender, EventArgs args)
    {
        try
        {
            string pText = txtP.Text.Trim();
            string qText = txtQ.Text.Trim();
            string eText = txtE.Text.Trim();

            if (pText == "" || qText == "" || eText == "")
            {
                MessageBox.Show("Vui lòng nhập đầy đủ p, q và e!");
                return;
            }

            p = BigInteger.Parse(pText);
            q = BigInteger.Parse(qText);
            eValue = BigInteger.Parse(eText);

            if (!IsPrime(p))
            {
                MessageBox.Show("p không phải là số nguyên tố!");
                return;
            }

            if (!IsPrime(q))
            {
                MessageBox.Show("q không phải là số nguyên tố!");
                return;
            }

            if (p == q)
            {
                MessageBox.Show("p và q phải là hai số nguyên tố khác nhau!");
                return;
            }

            n = p * q;

            phi = (p - 1) * (q - 1);

            if (eValue <= 1 || eValue >= phi)
            {
                MessageBox.Show("e phải thỏa mãn: 1 < e < φ(n)!");
                return;
            }

            if (Gcd(eValue, phi) != 1)
            {
                MessageBox.Show("e phải nguyên tố cùng nhau với φ(n), tức gcd(e, φ(n)) = 1!");
                return;
            }

            d = ModInverse(eValue, phi);

            hasKey = true;

            txtN.Text = n.ToString();
            txtPhi.Text = phi.ToString();
            txtD.Text = d.ToString();

            txtPublicKey.Text = "Kp = {" + eValue + ", " + n + "}";
            txtPrivateKey.Text = "Ks = {" + d + ", " + n + "}";

            lastPlainText = "";
            lastCipherText = "";

            lblStatus.Text = "Trạng thái: Sinh khóa thành công";

            MessageBox.Show("Sinh khóa RSA thành công!");
        }
        catch (Exception ex)
        {
            MessageBox.Show("Lỗi sinh khóa: " + ex.Message);
        }
    }

    // ================= HÀM MÃ HÓA THÔNG ĐIỆP =================
    private void EncryptAction(object sender, EventArgs args)
    {
        try
        {
            if (!IsKeyGenerated())
            {
                MessageBox.Show("Bạn cần sinh khóa RSA trước!");
                return;
            }

            string mode = cboMode.SelectedItem.ToString();

            if (mode == "Số nguyên")
            {
                EncryptNumber();
            }
            else
            {
                EncryptText();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show("Lỗi mã hóa: " + ex.Message);
        }
    }

    // ================= HÀM MÃ HÓA SỐ NGUYÊN =================
    private void EncryptNumber()
    {
        string plainText = txtPlainText.Text.Trim();

        if (plainText == "")
        {
            MessageBox.Show("Vui lòng nhập bản rõ M cần mã hóa!");
            return;
        }

        try
        {
            BigInteger m = BigInteger.Parse(plainText);

            if (m <= 0 || m >= n)
            {
                MessageBox.Show("M phải thỏa mãn: 0 < M < n!");
                return;
            }

            BigInteger c = ModularPower(m, eValue, n);

            txtCipherText.Text = c.ToString();

            lastPlainText = m.ToString();
            lastCipherText = c.ToString();

            lblStatus.Text = "Trạng thái: Mã hóa số nguyên thành công. C = " + c;

            MessageBox.Show("Mã hóa số nguyên thành công!");
        }
        catch
        {
            MessageBox.Show("Ở chế độ Số nguyên, bản rõ M phải là số nguyên!");
        }
    }

    // ================= HÀM MÃ HÓA VĂN BẢN =================
    private void EncryptText()
    {
        string plainText = txtPlainText.Text;

        if (plainText.Trim() == "")
        {
            MessageBox.Show("Vui lòng nhập văn bản cần mã hóa!");
            return;
        }

        if (n <= 255)
        {
            MessageBox.Show(
                "n = p × q phải lớn hơn 255 để mã hóa văn bản!\n" +
                "Bạn hãy chọn p, q lớn hơn.\n\n" +
                "Ví dụ:\n" +
                "p = 61, q = 53, e = 17"
            );
            return;
        }

        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

        List<string> cipherBlocks = new List<string>();

        foreach (byte b in plainBytes)
        {
            BigInteger m = new BigInteger((int)b);

            BigInteger c = ModularPower(m, eValue, n);

            cipherBlocks.Add(c.ToString());
        }

        string cipherText = string.Join(" ", cipherBlocks);

        txtCipherText.Text = cipherText;

        lastPlainText = plainText;
        lastCipherText = cipherText;

        lblStatus.Text = "Trạng thái: Mã hóa văn bản thành công. Có thể copy bản mã sang phần giải mã.";

        MessageBox.Show("Mã hóa văn bản thành công!");
    }

    // ================= HÀM GIẢI MÃ THÔNG ĐIỆP =================
    private void DecryptAction(object sender, EventArgs args)
    {
        try
        {
            if (!IsKeyGenerated())
            {
                MessageBox.Show("Bạn cần sinh khóa RSA trước!");
                return;
            }

            string cipherInput = txtCipherInput.Text.Trim();

            if (cipherInput == "")
            {
                MessageBox.Show("Vui lòng nhập bản mã cần giải mã!");
                return;
            }

            if (lastCipherText.Trim() != "")
            {
                string normalizedInput = NormalizeCipherText(cipherInput);
                string normalizedOriginal = NormalizeCipherText(lastCipherText);

                if (normalizedInput != normalizedOriginal)
                {
                    DialogResult confirm = MessageBox.Show(
                        "Bản mã nhập vào đã bị thay đổi so với bản mã được tạo ở phần mã hóa.\n" +
                        "Bạn có muốn tiếp tục giải mã bản mã đã bị thay đổi không?",
                        "Cảnh báo bản mã bị thay đổi",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning
                    );

                    lblStatus.Text = "Cảnh báo: Bản mã nhập vào đã bị thay đổi so với bản mã được tạo ở phần mã hóa.";

                    if (confirm != DialogResult.Yes)
                    {
                        return;
                    }
                }
            }

            string mode = cboMode.SelectedItem.ToString();

            if (mode == "Số nguyên")
            {
                DecryptNumber();
            }
            else
            {
                DecryptText();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show("Lỗi giải mã: " + ex.Message);
        }
    }

    // ================= HÀM GIẢI MÃ SỐ NGUYÊN =================
    private void DecryptNumber()
    {
        string cipherInput = txtCipherInput.Text.Trim();

        try
        {
            BigInteger c = BigInteger.Parse(cipherInput);

            if (c < 0 || c >= n)
            {
                MessageBox.Show("C phải thỏa mãn: 0 ≤ C < n!");
                return;
            }

            BigInteger m = ModularPower(c, d, n);

            txtDecryptedText.Text = m.ToString();

            if (lastPlainText != "" && m.ToString() == lastPlainText)
            {
                lblStatus.Text = "Trạng thái: Giải mã số nguyên thành công. Bản rõ trùng với bản rõ ban đầu.";
            }
            else
            {
                lblStatus.Text = "Trạng thái: Giải mã số nguyên xong. Bản rõ sau giải mã có thể đã khác bản rõ ban đầu.";
            }

            MessageBox.Show("Giải mã số nguyên thành công!");
        }
        catch
        {
            MessageBox.Show("Ở chế độ Số nguyên, bản mã C phải là số nguyên!");
        }
    }

    // ================= HÀM GIẢI MÃ VĂN BẢN =================
    private void DecryptText()
    {
        string cipherInput = txtCipherInput.Text.Trim();

        try
        {
            string[] blocks = cipherInput.Split(new char[] { ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);

            byte[] decryptedBytes = new byte[blocks.Length];

            for (int i = 0; i < blocks.Length; i++)
            {
                BigInteger c = BigInteger.Parse(blocks[i]);

                if (c < 0 || c >= n)
                {
                    MessageBox.Show("Bản mã C phải thỏa mãn: 0 ≤ C < n!");
                    return;
                }

                BigInteger m = ModularPower(c, d, n);

                int originalByte = (int)m;

                if (originalByte < 0 || originalByte > 255)
                {
                    MessageBox.Show("Giải mã lỗi! Có thể bạn nhập sai bản mã hoặc dùng sai khóa.");
                    return;
                }

                decryptedBytes[i] = (byte)originalByte;
            }

            string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            txtDecryptedText.Text = decryptedText;

            if (lastPlainText != "" && decryptedText == lastPlainText)
            {
                lblStatus.Text = "Trạng thái: Giải mã văn bản thành công. Bản rõ trùng với bản rõ ban đầu.";
            }
            else
            {
                lblStatus.Text = "Trạng thái: Giải mã văn bản xong. Bản rõ sau giải mã có thể đã khác bản rõ ban đầu.";
            }

            MessageBox.Show("Giải mã văn bản thành công!");
        }
        catch
        {
            MessageBox.Show("Ở chế độ Văn bản, bản mã chỉ được chứa các số cách nhau bằng dấu cách!");
        }
    }

    // ================= HÀM CHUẨN HÓA BẢN MÃ ĐỂ SO SÁNH =================
    private string NormalizeCipherText(string text)
    {
        string[] parts = text.Split(new char[] { ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);

        return string.Join(" ", parts);
    }

    // ================= HÀM TẢI FILE VÀO TEXTBOX =================
    private void LoadFileToTextBox(TextBox textBox)
    {
        try
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);

                textBox.Text = content;

                lblStatus.Text = "Trạng thái: Đã tải file " + Path.GetFileName(openFileDialog.FileName);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show("Lỗi tải file: " + ex.Message);
        }
    }

    // ================= HÀM LƯU TEXTBOX RA FILE =================
    private void SaveTextBoxToFile(TextBox textBox, string defaultFileName)
    {
        try
        {
            if (textBox.Text.Trim() == "")
            {
                MessageBox.Show("Không có nội dung để lưu!");
                return;
            }

            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.FileName = defaultFileName;
            saveFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";

            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                File.WriteAllText(saveFileDialog.FileName, textBox.Text, Encoding.UTF8);

                lblStatus.Text = "Trạng thái: Đã lưu file " + Path.GetFileName(saveFileDialog.FileName);

                MessageBox.Show("Lưu file thành công!");
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show("Lỗi lưu file: " + ex.Message);
        }
    }

    // ================= HÀM XÓA PHẦN MÃ HÓA =================
    private void ClearEncryptArea()
    {
        txtPlainText.Text = "";
        txtCipherText.Text = "";

        lastPlainText = "";
        lastCipherText = "";

        lblStatus.Text = "Trạng thái: Đã xóa phần mã hóa";
    }

    // ================= HÀM XÓA PHẦN GIẢI MÃ =================
    private void ClearDecryptArea()
    {
        txtCipherInput.Text = "";
        txtDecryptedText.Text = "";

        lblStatus.Text = "Trạng thái: Đã xóa phần giải mã";
    }

    // ================= HÀM THOÁT CHƯƠNG TRÌNH =================
    private void ExitProgram()
    {
        DialogResult confirm = MessageBox.Show(
            "Bạn có chắc chắn muốn thoát chương trình không?",
            "Xác nhận thoát",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question
        );

        if (confirm == DialogResult.Yes)
        {
            Application.Exit();
        }
    }

    // ================= HÀM KIỂM TRA ĐÃ SINH KHÓA CHƯA =================
    private bool IsKeyGenerated()
    {
        return hasKey;
    }

    // ================= HÀM MAIN CHẠY CHƯƠNG TRÌNH =================
    [STAThread]
    public static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new RSAGui());
    }
}