Есть два собеседника, которые регулярно обмениваются конфиденциальной информацией. Они стремятся защитить свои сообщения от несанкционированного доступа и возможных атак. Требуется разработать ПО для шифрования сообщений таким образом, чтобы обеспечить их конфиденциальность при передаче между участниками.

Должно быть реализовано два сервиса со стандартным API для взаимодействия. Нужно выбрать 3 алгоритма шифрования по одному алгоритму среди следующих типов шифрования и реализовать их:
- Шифр перестановки или замены
- Симметричное шифрование
- Асимметричное шифрование

API
1. /encrypt - на вход принимается открытое сообщение и метод шифрования, получаем зашифрованное сообщение.
2. /encrypt_and_send - на вход принимается открытое сообщение и метод шифрования, сообщение шифруется и отправляется на адрес собеседника (оба сервиса реализованы локально на ПК).
3. /send_encrypted_msg - на вход принимается зашифрованное сообщение и метод шифрования, сообщение отправляется на адрес собеседника.
4. /get_encrypted_msg - на вход принимается зашифрованное сообщение и метод шифрования, выводится открытое сообщение
5. /generate - на вход принимается метод шифрования, в соответсвии с методом шифрования генерируются необходимые ключи (закрытый и открытый).
6. /send_public_key - на вход принимается метод шифрования, в соответсвии с методом шифрования отправляется открытый ключ собеседнику.
7. /get_public_key - на вход принимается метод шифрования и открытый ключ от собеседника, открытый ключ сохраняется на стороне собеседника

