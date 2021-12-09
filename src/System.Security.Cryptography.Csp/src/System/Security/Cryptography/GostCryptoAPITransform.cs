using Internal.NativeCrypto;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Трансформ для гостового шифрования
    /// </summary>
    /// <remarks>
    /// Стандартный трасформ UniversalCryptoTransform через BasicSymmetricCipher 
    /// не поддердивает в частности поточные режимы без дополнения.
    /// Переписывать все классы ms желания нет, поэтому просто реализуем свой трансоформ
    /// </remarks>
    internal sealed class GostCryptoAPITransform : ICryptoTransform, IDisposable
    {
        /// <summary>
        /// Предыдущий блок. Используется для padiing.
        /// </summary>
        private byte[] depadBuffer_;
        /// <summary>
        /// HANDLE ключа.
        /// </summary>
        private SafeKeyHandle safeKeyHandle_;
        /// <summary>
        /// Провайдер для случайного генератора
        /// </summary>
        private SafeProvHandle _safeProvHandle;
        /// <summary>
        /// Размер блока.
        /// </summary>
        private int _blockSizeValue;
        /// <summary>
        /// Режим шифрования: зашифрования или расшифрования.
        /// </summary>
        private bool _encrypting;
        /// <summary>
        /// Синхропосылка
        /// </summary>
        private byte[] _ivValue;
        /// <summary>
        /// Режим шифрования.
        /// </summary>
        private CipherMode _modeValue;
        /// <summary>
        /// <see langword="true"/> для поточного шифрования, 
        /// <see langword="false"/> для блочного.
        /// </summary>
        private bool _isStream;
        /// <summary>
        /// Padding.
        /// </summary>
        private PaddingMode _paddingValue;

        /// <summary>
        /// Запрещаем создание нового объекта класса 
        /// <see cref="GostCryptoAPITransform"/>, без указания всех начальных 
        /// параметров.
        /// </summary>
        private GostCryptoAPITransform()
        {
        }

        /// <summary>
        /// Создание Transform.
        /// </summary>
        /// 
        /// <param name="cArgs">Размер используемого массива
        /// <c>rgArgIds</c> и <c>rgArgValues</c>.</param>
        /// <param name="rgArgIds">Массив KP_</param>
        /// <param name="rgArgValues">Массив значений SetKeyParam.</param>
        /// <param name="hKey">Ключ используемый для преобразования,
        /// ключ не дублируется.</param>
        /// <param name="hProv">Хэндл провайдера ключа, опционально используется для получения ДСЧ</param>
        /// <param name="padding">Padding</param>
        /// <param name="cipherChainingMode">Режим шифрования</param>
        /// <param name="blockSize">Размер блока</param>
        /// <param name="encrypting">Тип шифрования: (зашифрование, 
        /// расшифрование)</param>
        /// 
        /// <intdoc><para>ALGID задается SafeKeyHandle, feedbackSize
        /// для ГОСТа определен однозначно, salt для ГОСТ неприменимо.</para>
        /// <para>padding задает только возвращаемый padding, для установки
        /// padding внутрь handle используются массивы KP_; кроме того
        /// значения enum PaddingMode отличается от значений в 
        /// массиве значений KP_ (по wincrypt.h)</para>
        /// </intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        [SecurityCritical]
        internal GostCryptoAPITransform(
            int cArgs, int[] rgArgIds, object[] rgArgValues,
            SafeKeyHandle hKey,
            SafeProvHandle hProv,
            PaddingMode padding, 
            CipherMode cipherChainingMode,
            int blockSize,
            bool encrypting)
        {
            _blockSizeValue = blockSize;
            _modeValue = cipherChainingMode;
            _isStream = _modeValue == CipherMode.OFB
                || _modeValue == CipherMode.CFB;
            _paddingValue = padding;
            this._encrypting = encrypting;
            int[] numArray1 = new int[rgArgIds.Length];
            Array.Copy(rgArgIds, numArray1, rgArgIds.Length);
            object[] objArray1 = new object[rgArgValues.Length];
            for (int num2 = 0; num2 < rgArgValues.Length; num2++)
            {
                if (rgArgValues[num2] is byte[])
                {
                    byte[] buffer2 = (byte[])rgArgValues[num2];
                    byte[] buffer3 = new byte[buffer2.Length];
                    Array.Copy(buffer2, buffer3, buffer2.Length);
                    objArray1[num2] = buffer3;
                }
                else if (rgArgValues[num2] is int)
                {
                    objArray1[num2] = (int)rgArgValues[num2];
                }
                else if (rgArgValues[num2] is CipherMode)
                {
                    objArray1[num2] = (int)rgArgValues[num2];
                }
                else if (rgArgValues[num2] is PaddingMode)
                {
                    objArray1[num2] = (int)rgArgValues[num2];
                }
            }
            safeKeyHandle_ = hKey;
            _safeProvHandle = hProv;

            // Не добавляем ссылки на ключи и провайдеры
            // провайдер передан уже с addRef
            // ключ - получен через DuplicateKey

            for (int num3 = 0; num3 < cArgs; num3++)
            {
                switch (rgArgIds[num3])
                {
                    case GostConstants.KP_SV:
                    {
                        _ivValue = (byte[])objArray1[num3];
                        byte[] buffer1 = _ivValue;
                        CapiHelper.SetKeyParameter(safeKeyHandle_,
                            numArray1[num3], buffer1);
                        break;
                    }
                    case GostConstants.KP_PADDING:
                    {
                        CapiHelper.SetKeyParameter(safeKeyHandle_,
                            numArray1[num3], BitConverter.GetBytes((int)objArray1[num3]));
                        break;
                    }
                    case GostConstants.KP_MODE:
                    {
                        CapiHelper.SetKeyParameter(safeKeyHandle_,
                            numArray1[num3], BitConverter.GetBytes((int)objArray1[num3]));
                        break;
                    }
                    default:
                    {
                        throw new CryptographicException(SR.Argument_InvalidValue);
                    }
                }
            }
        }

        /// <summary>
        /// Освобождает все ресурсы, используемые объектом 
        /// <see cref="GostCryptoAPITransform"/>.
        /// </summary>
        /// 
        /// <remarks>Данный метод - упрощенный вариант вызова 
        /// <see cref="IDisposable.Dispose"/>.</remarks>
        public void Clear()
        {
            ((IDisposable)this).Dispose();
        }

        /// <summary>
        /// Освобождение ресурсов занятых экземпляром класса.
        /// </summary>
        /// 
        /// <param name="disposing"><see langword="true"/>, если разрешен 
        /// доступ к другим объектам, <see langword="false"/> - другие 
        /// объекты могут быть уничтожены.
        /// </param>
        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_ivValue != null)
                {
                    Array.Clear(_ivValue, 0, _ivValue.Length);
                    _ivValue = null;
                }
                if (depadBuffer_ != null)
                {
                    Array.Clear(depadBuffer_, 0, depadBuffer_.Length);
                    depadBuffer_ = null;
                }
            }
            if ((safeKeyHandle_ != null) && !safeKeyHandle_.IsClosed)
            {
                safeKeyHandle_.Dispose();
            }
            if ((_safeProvHandle != null) && !_safeProvHandle.IsClosed)
            {
                _safeProvHandle.Dispose();
            }
        }

        /// <summary>
        /// Сброс внутреннего состояния <see cref="GostCryptoAPITransform"/>
        /// в начальное, для проведения другой операции шифрования.
        /// </summary>
        /// 
        /// <remarks> 
        /// Метод <c>Reset</c> вызывается автоматически при вызове 
        /// <see cref="TransformFinalBlock"/>.
        /// Метод <c>Reset</c> не вызывается, когда, например, полученные 
        /// данные не могут быть расшифрованы. В этом случае вызывается 
        /// исключение, а метод <c>Reset</c> необходимо вызвать вручную. 
        /// </remarks>
        public void Reset()
        {
            depadBuffer_ = null;
            CapiHelper.EndCrypt(safeKeyHandle_, _encrypting);
        }

        /// <summary>
        /// Освобождает все ресурсы, используемые объектом 
        /// <see cref="GostCryptoAPITransform"/>.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Шифрование (зашифрование или расшифрование)
        /// заданной области входного массива байтов и в заданную 
        /// область выходного массива байтов.
        /// </summary>
        /// 
        /// <param name="inputBuffer">Входной массив байтов.</param>
        /// <param name="inputOffset">Смещение от начала входного 
        /// массива.</param>
        /// <param name="inputCount">Число обрабатываемых байтов входного 
        /// массива.</param>
        /// <param name="outputBuffer">Выходной массив байтов.</param>
        /// <param name="outputOffset">Смещение от начала выходного 
        /// массива.</param>
        /// 
        /// <returns>Количество записанных байтов.</returns>
        /// 
        /// <argnull name="inputBuffer" />
        /// <argnull name="outputBuffer" />
        /// 
        /// <exception cref="ArgumentException">Длина входного массива меньше 
        /// суммы смещения от его начала и числа обрабатываемых 
        /// байтов.</exception>
        /// 
        /// <exception cref="ArgumentOutOfRangeException">Если начальное
        /// смещение отрицательно.</exception>
        public int TransformBlock(byte[] inputBuffer, int inputOffset,
            int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputBuffer == null)
                throw new ArgumentNullException("inputBuffer");
            if (outputBuffer == null)
                throw new ArgumentNullException("outputBuffer");
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset", SR.ArgumentOutOfRange_NeedNonNegNum);
            if (((inputCount <= 0) || ((inputCount % InputBlockSize) != 0))
                || (inputCount > inputBuffer.Length))
            {
                throw new ArgumentException(SR.Argument_InvalidValue);
            }
            if ((inputBuffer.Length - inputCount) < inputOffset)
            {
                throw new ArgumentException(SR.Argument_InvalidValue);
            }
            if (_encrypting)
            {
                return CapiHelper.EncryptDataCp(_safeProvHandle, safeKeyHandle_, inputBuffer,
                    inputOffset, inputCount, ref outputBuffer, outputOffset,
                    _paddingValue, false, _isStream);
            }
            if ((_paddingValue == PaddingMode.Zeros)
                || (_paddingValue == PaddingMode.None))
            {
                return CapiHelper.DecryptDataCp(safeKeyHandle_, inputBuffer,
                    inputOffset, inputCount, ref outputBuffer, outputOffset,
                    _paddingValue, false);
            }
            if (depadBuffer_ == null)
            {
                depadBuffer_ = new byte[InputBlockSize];
                int num1 = inputCount - InputBlockSize;
                Array.Copy(inputBuffer, inputOffset + num1,
                    depadBuffer_, 0, InputBlockSize);
                return CapiHelper.DecryptDataCp(safeKeyHandle_, inputBuffer,
                    inputOffset, num1, ref outputBuffer, outputOffset,
                    _paddingValue, false);
            }
            int num2 = CapiHelper.DecryptDataCp(safeKeyHandle_, depadBuffer_,
                0, depadBuffer_.Length, ref outputBuffer, outputOffset,
                _paddingValue, false);
            outputOffset += OutputBlockSize;
            int num3 = inputCount - InputBlockSize;
            Array.Copy(inputBuffer, inputOffset + num3,
                depadBuffer_, 0, InputBlockSize);
            num2 = CapiHelper.DecryptDataCp(safeKeyHandle_, inputBuffer,
                inputOffset, num3, ref outputBuffer, outputOffset,
                _paddingValue, false);
            return OutputBlockSize + num2;
        }

        /// <summary>
        /// Шифрование (зашифрование или расшифрование) заключительного
        /// массива байтов.
        /// </summary>
        /// 
        /// <param name="inputBuffer">Входной массив байтов.</param>
        /// <param name="inputOffset">Смещение от начала входного 
        /// массива.</param>
        /// <param name="inputCount">Число обрабатываемых байтов входного 
        /// массива.</param>
        /// 
        /// <returns>Зашифрованный или расшифрованный оконечный 
        /// блок.</returns>
        /// 
        /// <argnull name="inputBuffer" />
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="inputOffset"/> меньше нуля.</exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="inputCount"/> меньше нуля или 
        /// входной блок выходит за границы массива.</exception>
        /// <exception cref="CryptographicException">При расшифровании
        /// в блочном режиме массива байтов с разером не кратным
        /// размеру блока.</exception>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset,
            int inputCount)
        {
            if (inputBuffer == null)
                throw new ArgumentNullException("inputBuffer");
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset",
                    SR.ArgumentOutOfRange_NeedNonNegNum);
            if ((inputCount < 0) || (inputCount > inputBuffer.Length))
                throw new ArgumentException(
                    SR.Argument_InvalidValue);
            if ((inputBuffer.Length - inputCount) < inputOffset)
                throw new ArgumentException(SR.Argument_InvalidValue);

            if (_encrypting)
            {
                byte[] buffer1 = null;
                CapiHelper.EncryptDataCp(_safeProvHandle, safeKeyHandle_, inputBuffer, inputOffset,
                    inputCount, ref buffer1, 0, _paddingValue, true, _isStream);
                Reset();
                return buffer1;
            }
            // На поточных алгоритмах не проверяем соответствие длин.
            if (_isStream)
            {
                byte[] buffer2 = null;
                CapiHelper.DecryptDataCp(safeKeyHandle_, inputBuffer, inputOffset,
                    inputCount, ref buffer2, 0, _paddingValue, true);
                Reset();
                return buffer2;
            }
            if ((inputCount % InputBlockSize) != 0)
            {
                throw new CryptographicException(SR.Argument_InvalidValue);
            }
            if (depadBuffer_ == null)
            {
                byte[] buffer2 = null;
                CapiHelper.DecryptDataCp(safeKeyHandle_, inputBuffer, inputOffset,
                    inputCount, ref buffer2, 0, _paddingValue, true);
                Reset();
                return buffer2;
            }
            byte[] buffer3 = new byte[depadBuffer_.Length + inputCount];
            Array.Copy(depadBuffer_, 0, buffer3, 0, depadBuffer_.Length);
            Array.Copy(inputBuffer, inputOffset, buffer3, depadBuffer_.Length,
                inputCount);
            byte[] buffer4 = null;
            CapiHelper.DecryptDataCp(safeKeyHandle_, buffer3, 0, buffer3.Length,
                ref buffer4, 0, _paddingValue, true);
            Reset();
            return buffer4;
        }

        /// <summary>
        /// Получает значение, указывающее, можно ли использовать 
        /// преобразование повторно.
        /// </summary>
        /// 
        /// <value>Всегда <see langword="true"/>.</value>
        public bool CanReuseTransform
        {
            get
            {
                return true;
            }
        }

        /// <summary>
        /// Получает значение, указывающее на возможность преобразования 
        /// нескольких блоков.
        /// </summary>
        /// <value>Всегда <see langword="true"/>.</value>
        public bool CanTransformMultipleBlocks
        {
            get
            {
                return true;
            }
        }

        /// <summary>
        /// Получает размер входного блока в байтах.
        /// </summary>
        /// 
        /// <value>размер входного блока в байтах</value>
        public int InputBlockSize
        {
            get
            {
                return (_blockSizeValue / 8);
            }
        }

        /// <summary>
        /// Получает дескриптор ключа.
        /// </summary>
        /// 
        /// <unmanagedperm action="Demand" />
        internal SafeKeyHandle KeyHandle
        {
            [SecurityCritical]
            get
            {
                return safeKeyHandle_;
            }
        }

        /// <summary>
        /// Получает размер выходного блока в байтах.
        /// </summary>
        /// 
        /// <value>размер входного блока в байтах</value>
        public int OutputBlockSize
        {
            get
            {
                return (_blockSizeValue / 8);
            }
        }
    }
}
