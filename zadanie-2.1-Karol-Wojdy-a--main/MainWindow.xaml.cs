using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace zadanie_2._1_karol_wojdyla;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// KeyForge Password Generator in C# (.NET 9 WPF)
/// </summary>
public partial class MainWindow : Window
{
    private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    private const string NumberChars = "0123456789";
    private const string SymbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~";
    private const string AmbiguousChars = "1lI0O8B";

    private string _generatedPassword = string.Empty;
    private bool _isPasswordVisible = true;
    private readonly List<string> _history = new();
    private readonly DispatcherTimer _toastTimer = new();
    private bool _isInitialized = false;

    public MainWindow()
    {
        InitializeComponent();

        _toastTimer.Interval = TimeSpan.FromMilliseconds(1800);
        _toastTimer.Tick += (s, e) =>
        {
            CopyToastBorder.Visibility = Visibility.Collapsed;
            _toastTimer.Stop();
        };

        _isInitialized = true;
        GeneratePassword();
    }

    /// <summary>
    /// Generates a cryptographically secure random password based on selected options.
    /// </summary>
    private void GeneratePassword()
    {
        if (!_isInitialized) return;

        int length = (int)LengthSlider.Value;
        bool useUpper = UppercaseCheckBox.IsChecked == true;
        bool useLower = LowercaseCheckBox.IsChecked == true;
        bool useNumbers = NumbersCheckBox.IsChecked == true;
        bool useSymbols = SymbolsCheckBox.IsChecked == true;
        bool excludeAmbiguous = ExcludeAmbiguousCheckBox.IsChecked == true;
        bool guaranteeAll = GuaranteeAllCheckBox.IsChecked == true;

        // Ensure at least one character set is selected
        if (!useUpper && !useLower && !useNumbers && !useSymbols)
        {
            LowercaseCheckBox.IsChecked = true;
            useLower = true;
        }

        string Filter(string source)
        {
            if (!excludeAmbiguous) return source;
            return new string(source.Where(c => !AmbiguousChars.Contains(c)).ToArray());
        }

        var pools = new List<string>();
        if (useUpper) pools.Add(Filter(UppercaseChars));
        if (useLower) pools.Add(Filter(LowercaseChars));
        if (useNumbers) pools.Add(Filter(NumberChars));
        if (useSymbols) pools.Add(Filter(SymbolChars));

        pools = pools.Where(p => !string.IsNullOrEmpty(p)).ToList();
        if (pools.Count == 0) return;

        string allChars = string.Concat(pools);
        var resultChars = new List<char>();

        // Guarantee at least one character from each selected category
        if (guaranteeAll && length >= pools.Count)
        {
            foreach (var pool in pools)
            {
                int index = RandomNumberGenerator.GetInt32(pool.Length);
                resultChars.Add(pool[index]);
            }
        }

        // Fill remainder of password length
        while (resultChars.Count < length)
        {
            int index = RandomNumberGenerator.GetInt32(allChars.Length);
            resultChars.Add(allChars[index]);
        }

        // Cryptographic Fisher-Yates shuffle
        for (int i = resultChars.Count - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(i + 1);
            (resultChars[i], resultChars[j]) = (resultChars[j], resultChars[i]);
        }

        _generatedPassword = new string(resultChars.ToArray());
        UpdatePasswordDisplay();
        UpdateStrengthMetrics(_generatedPassword);
        AddToHistory(_generatedPassword);
    }

    private void UpdatePasswordDisplay()
    {
        if (string.IsNullOrEmpty(_generatedPassword))
        {
            PasswordTextBox.Text = "Kliknij Generuj...";
            return;
        }

        if (_isPasswordVisible)
        {
            PasswordTextBox.Text = _generatedPassword;
            ToggleVisibilityBtn.Content = "👁️ Ukryj";
        }
        else
        {
            PasswordTextBox.Text = new string('●', _generatedPassword.Length);
            ToggleVisibilityBtn.Content = "👁️ Pokaż";
        }
    }

    /// <summary>
    /// Calculates entropy in bits and estimates crack resistance.
    /// </summary>
    private void UpdateStrengthMetrics(string password)
    {
        if (string.IsNullOrEmpty(password)) return;

        int poolSize = 0;
        if (password.Any(char.IsLower)) poolSize += 26;
        if (password.Any(char.IsUpper)) poolSize += 26;
        if (password.Any(char.IsDigit)) poolSize += 10;
        if (password.Any(c => !char.IsLetterOrDigit(c))) poolSize += 32;

        if (poolSize == 0) poolSize = 1;

        double entropy = Math.Round(password.Length * Math.Log2(poolSize));
        EntropyLabel.Text = entropy.ToString();

        // Evaluate strength levels
        if (entropy < 36)
        {
            StrengthLabel.Text = "Bardzo słabe";
            StrengthLabel.Foreground = new SolidColorBrush(Color.FromRgb(239, 68, 68)); // Red
            StrengthProgressBar.Value = 25;
            StrengthProgressBar.Foreground = new SolidColorBrush(Color.FromRgb(239, 68, 68));
            CrackTimeLabel.Text = "🕒 Szacowany czas na złamanie: < 1 sekunda (podatne na atak)";
        }
        else if (entropy < 55)
        {
            StrengthLabel.Text = "Umiarkowane";
            StrengthLabel.Foreground = new SolidColorBrush(Color.FromRgb(245, 158, 11)); // Amber
            StrengthProgressBar.Value = 50;
            StrengthProgressBar.Foreground = new SolidColorBrush(Color.FromRgb(245, 158, 11));
            CrackTimeLabel.Text = "🕒 Szacowany czas na złamanie: kilka godzin / dni";
        }
        else if (entropy < 75)
        {
            StrengthLabel.Text = "Dobre";
            StrengthLabel.Foreground = new SolidColorBrush(Color.FromRgb(59, 130, 246)); // Blue
            StrengthProgressBar.Value = 75;
            StrengthProgressBar.Foreground = new SolidColorBrush(Color.FromRgb(59, 130, 246));
            CrackTimeLabel.Text = "🕒 Szacowany czas na złamanie: setki lat (odporne)";
        }
        else if (entropy < 100)
        {
            StrengthLabel.Text = "Bardzo silne";
            StrengthLabel.Foreground = new SolidColorBrush(Color.FromRgb(16, 185, 129)); // Emerald
            StrengthProgressBar.Value = 90;
            StrengthProgressBar.Foreground = new SolidColorBrush(Color.FromRgb(16, 185, 129));
            CrackTimeLabel.Text = "🕒 Szacowany czas na złamanie: miliony lat (zgodne z NIST & OWASP)";
        }
        else
        {
            StrengthLabel.Text = "Nieprzeniknione";
            StrengthLabel.Foreground = new SolidColorBrush(Color.FromRgb(168, 85, 247)); // Purple
            StrengthProgressBar.Value = 100;
            StrengthProgressBar.Foreground = new SolidColorBrush(Color.FromRgb(168, 85, 247));
            CrackTimeLabel.Text = "🕒 Szacowany czas na złamanie: miliardy lat (odporne na superkomputery)";
        }
    }

    private void AddToHistory(string password)
    {
        if (string.IsNullOrEmpty(password)) return;
        if (_history.Count > 0 && _history[0] == password) return;

        _history.Insert(0, password);
        if (_history.Count > 25) _history.RemoveAt(_history.Count - 1);

        HistoryCountLabel.Text = _history.Count.ToString();
        HistoryListBox.ItemsSource = null;
        HistoryListBox.ItemsSource = _history;
    }

    private void CopyToClipboard(string text)
    {
        if (string.IsNullOrEmpty(text)) return;

        try
        {
            Clipboard.SetText(text);
            CopyToastBorder.Visibility = Visibility.Visible;
            _toastTimer.Stop();
            _toastTimer.Start();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Nie udało się skopiować do schowka: {ex.Message}", "Błąd", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // --- UI Event Handlers ---

    private void RefreshBtn_Click(object sender, RoutedEventArgs e) => GeneratePassword();

    private void MainGenerateBtn_Click(object sender, RoutedEventArgs e) => GeneratePassword();

    private void CopyBtn_Click(object sender, RoutedEventArgs e) => CopyToClipboard(_generatedPassword);

    private void ToggleVisibilityBtn_Click(object sender, RoutedEventArgs e)
    {
        _isPasswordVisible = !_isPasswordVisible;
        UpdatePasswordDisplay();
    }

    private void LengthSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (LengthValueText != null)
        {
            LengthValueText.Text = ((int)e.NewValue).ToString();
        }
        GeneratePassword();
    }

    private void Option_Changed(object sender, RoutedEventArgs e) => GeneratePassword();

    // --- Preset Click Handlers ---

    private void PresetUltra_Click(object sender, RoutedEventArgs e)
    {
        LengthSlider.Value = 24;
        UppercaseCheckBox.IsChecked = true;
        LowercaseCheckBox.IsChecked = true;
        NumbersCheckBox.IsChecked = true;
        SymbolsCheckBox.IsChecked = true;
        ExcludeAmbiguousCheckBox.IsChecked = false;
        GuaranteeAllCheckBox.IsChecked = true;
        GeneratePassword();
    }

    private void PresetBalanced_Click(object sender, RoutedEventArgs e)
    {
        LengthSlider.Value = 16;
        UppercaseCheckBox.IsChecked = true;
        LowercaseCheckBox.IsChecked = true;
        NumbersCheckBox.IsChecked = true;
        SymbolsCheckBox.IsChecked = true;
        ExcludeAmbiguousCheckBox.IsChecked = false;
        GuaranteeAllCheckBox.IsChecked = true;
        GeneratePassword();
    }

    private void PresetReadable_Click(object sender, RoutedEventArgs e)
    {
        LengthSlider.Value = 16;
        UppercaseCheckBox.IsChecked = true;
        LowercaseCheckBox.IsChecked = true;
        NumbersCheckBox.IsChecked = true;
        SymbolsCheckBox.IsChecked = true;
        ExcludeAmbiguousCheckBox.IsChecked = true;
        GuaranteeAllCheckBox.IsChecked = true;
        GeneratePassword();
    }

    private void PresetPin_Click(object sender, RoutedEventArgs e)
    {
        LengthSlider.Value = 6;
        UppercaseCheckBox.IsChecked = false;
        LowercaseCheckBox.IsChecked = false;
        NumbersCheckBox.IsChecked = true;
        SymbolsCheckBox.IsChecked = false;
        ExcludeAmbiguousCheckBox.IsChecked = false;
        GuaranteeAllCheckBox.IsChecked = false;
        GeneratePassword();
    }

    private void HistoryListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (HistoryListBox.SelectedItem is string selectedPassword)
        {
            CopyToClipboard(selectedPassword);
        }
    }

    private void ClearHistoryBtn_Click(object sender, RoutedEventArgs e)
    {
        _history.Clear();
        HistoryListBox.ItemsSource = null;
        HistoryCountLabel.Text = "0";
    }

    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Space)
        {
            GeneratePassword();
            e.Handled = true;
        }
    }
}