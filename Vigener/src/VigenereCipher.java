import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class VigenereCipher {

    public static String encrypt(String text, String key, String alphabet) {
        StringBuilder result = new StringBuilder();
        key = key.toLowerCase();
        int keyIndex = 0;
        int alphabetLength = alphabet.length();
        for (char c : text.toCharArray()) {
            if (!alphabet.contains(String.valueOf(c).toLowerCase())){
                result.append(c);
                continue;
            }
            int charIndex = alphabet.indexOf(Character.toLowerCase(c));
            boolean isUpper = Character.isUpperCase(c);
            int shift = alphabet.indexOf(key.charAt(keyIndex));
            char newChar = alphabet.charAt((charIndex + shift) % alphabetLength);
            result.append(isUpper ? newChar : Character.toLowerCase(newChar));
            keyIndex = (keyIndex + 1) % key.length();
        }
        return result.toString();
    }


    private static final String alphabet = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя";
    private static final int alphabetSize = alphabet.length();

    private static final Map<Character, Double> russianFreq = new HashMap<>() {{
        put('а', 0.0801); put('б', 0.0159); put('в', 0.0454); put('г', 0.0170); put('д', 0.0298);
        put('е', 0.0845); put('ё', 0.0004); put('ж', 0.0094); put('з', 0.0165); put('и', 0.0735);
        put('й', 0.0121); put('к', 0.0349); put('л', 0.0440); put('м', 0.0321); put('н', 0.0670);
        put('о', 0.1097); put('п', 0.0281); put('р', 0.0473); put('с', 0.0547); put('т', 0.0626);
        put('у', 0.0262); put('ф', 0.0026); put('х', 0.0097); put('ц', 0.0048); put('ч', 0.0144);
        put('ш', 0.0073); put('щ', 0.0036); put('ъ', 0.0004); put('ы', 0.0190); put('ь', 0.0174);
        put('э', 0.0032); put('ю', 0.0064); put('я', 0.0201);
    }};

    private static Map<Integer, Character> symlov = new HashMap<>();

    public static String cleanText(String text) {
        text = text.toLowerCase();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!alphabet.contains(String.valueOf(c))) {
                symlov.put(i, c);
            }
        }
        return text.replaceAll("[^" + alphabet + "]", "");
    }

    public static double indexOfCoincidence(String text) {
        int N = text.length();
        if (N <= 1) {
            return 0;
        }
        //Cоздается словарь frequencies, где ключ — символ, значение — количество его появлений в тексте.
        Map<Character, Long> frequencies = text.chars()
                .mapToObj(ch -> (char) ch)
                .collect(Collectors.groupingBy(ch -> ch, Collectors.counting()));
        //вычисляется индекс совпадений по формуле
        double ic = frequencies.values().stream()
                .mapToDouble(f -> f * (f - 1))
                .sum() / (N * (N - 1.0));
        return ic;
    }

    public static Integer kasiskiExamination(String ciphertext, int minSeqLength, int maxKeyLength) {
        //Проход по тексту с шагом в 1 символ.
        //Каждая подстрока длиной minSeqLength добавляется в Map, где ключ — подстрока, значение —
        // список позиций её вхождений.
        Map<String, List<Integer>> sequences = new HashMap<>();
        for (int i = 0; i <= ciphertext.length() - minSeqLength; i++) {
            String seq = ciphertext.substring(i, i + minSeqLength);
            sequences.computeIfAbsent(seq, k -> new ArrayList<>()).add(i);
        }

        //Отбор только повторяющихся последовательностей
        //Фильтруются только те последовательности, которые встречаются более одного раза.
        Map<String, List<Integer>> repeatedSequences = sequences.entrySet().stream()
                .filter(entry -> entry.getValue().size() > 1)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        //Для каждой последовательности вычисляются расстояния между её повторяющимися позициями.
        //Например, "ABC" в позициях 5 и 25 → расстояние = 20.
        List<Integer> spacings = new ArrayList<>();
        for (List<Integer> locs : repeatedSequences.values()) {
            for (int i = 0; i < locs.size() - 1; i++) {
                spacings.add(locs.get(i + 1) - locs.get(i));
            }
        }

        //Для каждого расстояния находятся все делители от 2 до maxKeyLength.
        //Если расстояние = 20, делители: 2, 4, 5, 10.
        List<Integer> possibleKeyLengths = new ArrayList<>();
        for (int spacing : spacings) {
            for (int i = 2; i <= Math.min(spacing, maxKeyLength); i++) {
                if (spacing % i == 0) {
                    possibleKeyLengths.add(i);
                }
            }
        }

        if (possibleKeyLengths.isEmpty()) {
            return 0;
        }

        //Создается таблица, в которой подсчитывается, сколько раз встречается каждый делитель.
        Map<Integer, Long> countMap = possibleKeyLengths.stream()
                .collect(Collectors.groupingBy(i -> i, Collectors.counting()));

        if (countMap.isEmpty()) {
            return 0;
        }

        //Определение наиболее вероятной длины ключа
        //Из всех делителей выбирается тот, который встречался чаще всего.
        //Если таких несколько — возвращается максимальный из них.
        long maxCount = Collections.max(countMap.values());
        List<Integer> candidates = countMap.entrySet().stream()
                .filter(entry -> entry.getValue() == maxCount)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());

        return Collections.max(candidates);
    }

    public static int estimateKeyLengthIc(String ciphertext, int maxKeyLength) {
        //Список для хранения: длина ключа → средний IoC
        List<Map.Entry<Integer, Double>> ics = new ArrayList<>();
        //Пробуем ключи длиной от 1 до maxKeyLength.
        for (int keyLength = 1; keyLength <= maxKeyLength; keyLength++) {
            List<Double> icValues = new ArrayList<>();
            //Делим шифртекст на keyLength подстрок
            //Пример: для текста ATTACKATDAWN и ключа длиной 3:
            //подстрока 1: A C T A (позиции 0,3,6,9)
            //подстрока 2: T K D (позиции 1,4,7,10)
            //подстрока 3: T A W N (позиции 2,5,8,11)
            for (int i = 0; i < keyLength; i++) {
                int finalKeyLength = keyLength;
                int finalI = i;
                //с помощью IntStream мы собираем каждый i-й символ из каждой keyLength-группы.
                String subsequence = IntStream.range(i, ciphertext.length())
                        .filter(n -> n % finalKeyLength == finalI)
                        .mapToObj(ciphertext::charAt)
                        .map(String::valueOf)
                        .collect(Collectors.joining());
                //indexOfCoincidence() вычисляет статистическую вероятность того, что два случайно выбранных символа будут одинаковыми.
                //≈0.065 — для английского текста.
                //≈0.038 — для случайного текста.
                //Если IoC ближе к 0.065 — значит, подстрока похожа на открытый текст → правильная длина ключа.
                double ic = indexOfCoincidence(subsequence);
                icValues.add(ic);
            }
            //среднее значение IoC для всех подстрок
            double averageIc = icValues.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
            ics.add(new AbstractMap.SimpleEntry<>(keyLength, averageIc));
        }
        //Находим такую длину ключа, при которой средний индекс совпадений максимален → скорее всего,
        // это и есть длина ключа.
        return ics.stream()
                .max(Comparator.comparingDouble(Map.Entry::getValue))
                .map(Map.Entry::getKey)
                .orElse(0);
    }
    //Если длина ключа угадана верно, то каждый "подтекст" — это результат простого сдвига шифра Цезаря,
    // а значит он сохранит распределение символов исходного языка → высокий IoC.
    //Если длина ключа угадана неверно, подстроки получаются случайными наборами символов → IoC близок к
    // случайному (~0.038).


    public static int estimateKeyLengthCombined(String ciphertext, int maxKeyLength) {
        //Метод Казиски ищет повторяющиеся последовательности длиной ≥ 4, измеряет расстояния между ними и
        // анализирует общие делители этих расстояний (делители = возможные длины ключа).
        int keyLengthKasiski = kasiskiExamination(ciphertext, 4, maxKeyLength);
        if (keyLengthKasiski != 0 && 1 < keyLengthKasiski && keyLengthKasiski <= maxKeyLength) {
            return keyLengthKasiski;
        }
        //Если Казиски не сработал, применяется метод оценки по индексу совпадений.
        int keyLengthIc = estimateKeyLengthIc(ciphertext, maxKeyLength);
        return keyLengthIc;
    }

    //определяет оптимальный сдвиг (ключ) для одного символа ключа шифра Виженера, используя χ²-критерий
    // (хи-квадрат) для сравнения частот символов в зашифрованном тексте с ожидаемыми частотами символов
    // русского языка.
    public static int calculateShift(String subtext, Map<Character, Double> russianFreq) {
        double minChiSquared = Double.MAX_VALUE;
        int bestShift = 0;
        //Применяется каждый возможный сдвиг (от 0 до размера алфавита - 1),
        // как будто подстрока была зашифрована этим сдвигом.
        for (int shift = 0; shift < alphabetSize; shift++) {
            StringBuilder shiftedSubtext = new StringBuilder();
            for (char c : subtext.toCharArray()) {
                //Символы сдвигаются обратно на shift, чтобы "расшифровать" и
                // получить потенциальный исходный текст.
                int index = alphabet.indexOf(c);
                int shiftedIndex = (index - shift + alphabetSize) % alphabetSize;
                shiftedSubtext.append(alphabet.charAt(shiftedIndex));
            }
            Map<Character, Integer> frequencies = new HashMap<>();
            for (char c : shiftedSubtext.toString().toCharArray()) {
                //Подсчет частоты символов в расшифрованной строке
                frequencies.put(c, frequencies.getOrDefault(c, 0) + 1);
            }
            int total = shiftedSubtext.length();
            double chiSquared = 0;
            for (char letter : alphabet.toCharArray()) {
                int observed = frequencies.getOrDefault(letter, 0);
                double expected = total * russianFreq.getOrDefault(letter, 0.0);
                if (expected > 0) {
                    //Вычисление хи-квадрат статистики
                    //Сравниваются наблюдаемые частоты с ожидаемыми. Чем ближе они, тем ниже χ²
                    chiSquared += Math.pow(observed - expected, 2) / expected;
                }
            }
            //Выбирается тот сдвиг, при котором статистика минимальна — то есть подстрока после
            // обратного сдвига максимально похожа на нормальный русский текст
            if (chiSquared < minChiSquared) {
                minChiSquared = chiSquared;
                bestShift = shift;
            }
        }
        return bestShift;
    }

    public static String recoverKey(String ciphertext, int keyLength, Map<Character, Double> russianFreq) {
        StringBuilder key = new StringBuilder();
        //Цикл по каждой позиции в ключе
        for (int i = 0; i < keyLength; i++) {
            StringBuilder subtext = new StringBuilder();
            //Извлекает "подстроку" для этой позиции
            for (int j = i; j < ciphertext.length(); j += keyLength) {
                subtext.append(ciphertext.charAt(j));
            }
            //Вычисляет сдвиг (букву ключа) по χ²
            //Ищет сдвиг, при котором частоты максимально похожи на русский язык
            int shiftRecovered = calculateShift(subtext.toString(), russianFreq);
            // Получает букву ключа
            char keyLetter = alphabet.charAt(shiftRecovered);
            key.append(keyLetter);
        }
        return key.toString();
    }

    public static String decrypt(String text, String key, String alphabet) {
        StringBuilder result = new StringBuilder();
        key = key.toLowerCase();
        int keyIndex = 0;
        int alphabetLength = alphabet.length();
        int i = 0;
        for (char c : text.toCharArray()) {
            int charIndex = alphabet.indexOf(Character.toLowerCase(c));
            boolean isUpper = Character.isUpperCase(c);
            int shift = alphabet.indexOf(key.charAt(keyIndex));
            char newChar = alphabet.charAt((charIndex - shift + alphabetLength) % alphabetLength);
            if (symlov.containsKey(i)) {
                result.append(symlov.get(i));
                i++;
                if (symlov.containsKey(i)) {
                    while (symlov.containsKey(i)) {
                        result.append(symlov.get(i));
                        i++;
                    }
                }
            }
            i++;
            result.append(isUpper ? newChar : Character.toLowerCase(newChar));
            keyIndex = (keyIndex + 1) % key.length();
        }
        return result.toString();
    }

    public static void main(String[] args) {

        String text = "Русские народные сказки воспитали не одно поколение детей, так как всегда отличались не просто интересным, но в первую очередь поучительным содержанием. Под эти сказки каждый вечер засыпали наши родители, бабушки и дедушки, и сегодня они остаются такими же актуальными. В этом разделе вы найдете большую коллекцию русских народных сказок, в которых сможете встретить и уже хорошо знакомых вам, полюбившихся персонажей, таких как Колобок, Илья Муромец, Елена премудрая, и возможно, откроете для себя новых героев.";

        String key = "дом";

        String encrypted = encrypt(text, key, alphabet);
        System.out.println("Зашифрованный текст: " + encrypted);

        String cleanedCiphertext = cleanText(encrypted);

        int keyLength = estimateKeyLengthCombined(cleanedCiphertext, 15);
        key = recoverKey(cleanedCiphertext, keyLength, russianFreq);
        System.out.println("\nКлюч: " +key);

        String plaintext = decrypt(cleanedCiphertext, key, alphabet);
        System.out.println("Расшифрованный текст:");
        System.out.println(plaintext);
    }
}

//1. Зависимость от длины и качества текста
//Короткий текст — мало повторяющихся последовательностей, из-за чего Kasiski может не найти делителей длины ключа.
//
//Небольшое количество повторов снижает точность определения длины ключа.
//
//Если текст слишком мал или слишком зашумлён, статистика по частотам и IoC сильно искажается.
//
//2. Сложность с нестандартными алфавитами
//Твой код рассчитан на русский алфавит, но если в тексте есть знаки, цифры, пробелы и прочее — их нужно вычищать или обрабатывать отдельно.
//
//Использование неочищенного текста приводит к неправильным частотам и сдвигам.
//
//3. Ограничение по максимальной длине ключа
//В функции estimateKeyLengthCombined и estimateKeyLengthIc стоит ограничение по максимальной длине ключа.
//
//Если реальная длина ключа больше этого значения — она не будет найдена.
//
//4. Погрешности из-за приближённости частот
//Частотный анализ основывается на усреднённых статистиках русского языка, которые не всегда совпадают с конкретным текстом.
//
//Если текст тематически узкий или стилистически необычный — частоты могут смещаться, что ухудшает качество восстановления ключа.
//
//5. Предположение о шифре Виженера
//Этот метод работает только если текст действительно зашифрован классическим Виженером (цикличное повторение ключа, простой сдвиг).
//
//Если применён более сложный вариант (например, автоключ, полиграфические замены, или ключ меняется) — метод не сработает.
//
//6. Kasiski требует минимум длины повторяющейся последовательности
//В твоём коде минимум длины последовательности жёстко задан (minSeqLength = 4).
//
//Если в тексте мало таких повторов длиной 4 и более — метод будет бесполезен.
//
//7. Индекс совпадений — статистический метод
//IoC не всегда даёт однозначный ответ, особенно при небольшом количестве данных или сложном ключе.
//
//Может быть несколько «локальных максимумов» IoC для разных длин ключа.
//
//8. Не учитывается возможность ошибок и шума
//В реальных данных может быть искажение, ошибки, случайные символы.
//
//Алгоритм не предусматривает устойчивость к шуму.
