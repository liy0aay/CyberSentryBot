from telebot import types

SAFETY_QUESTIONS = [
    {
        "question": "Как злоумышленники могут получить ваш пароль, даже если сайт, которым вы пользуетесь, сам не подвергся взлому?",
        "options": [
            "Через утечку базы данных с другого сервиса",
            "С помощью автоматического подбора паролей",
            "Через фишинг и поддельные страницы входа",
            "Все перечисленное"
        ],
        "correct": 3,
        "explanation": "Все перечисленные методы могут быть использованы для кражи паролей."
    },
    {
        "question": "Каким способом можно подделать URL сайта, чтобы он выглядел как настоящий?",
        "options": [
            "Использовать поддельные сертификаты безопасности",
            "Создать домен с похожими символами",
            "Вставить вредоносный JavaScript-код в URL-адрес",
            "Все вышеуказанные методы"
        ],
        "correct": 3,
        "explanation": "Все перечисленные методы могут использоваться для маскировки URL."
    },
    {
        "question": "Как злоумышленники могут похитить данные вашей банковской карты без вашего ведома?",
        "options": [
            "Используя скрытые кейлоггеры или шпионское ПО",
            "Подменяя форму оплаты на зараженных сайтах",
            "Сканируя данные карты через NFC",
            "Все вышеуказанные методы"
        ],
        "correct": 3,
        "explanation": "Все эти методы представляют угрозу безопасности."
    },
    {
        "question": "Что из перечисленного является наименее надежным способом хранения паролей?",
        "options": [
            "Использование менеджера паролей",
            "Запись паролей в зашифрованный документ",
            "Запоминание всех паролей в голове",
            "Хранение всех паролей в текстовом файле"
        ],
        "correct": 3,
        "explanation": "Хранение паролей в обычном текстовом файле — крайне ненадежно."
    },
    {
        "question": "Что делает злоумышленник при атаке типа Man-in-the-Middle?",
        "options": [
            "Изменяет передаваемые данные между вами и сайтом",
            "Использует ваш IP-адрес для анонимного серфинга в сети",
            "Встраивает вредоносную рекламу в веб-страницы",
            "Отправляет вредоносные письма с поддельных доменов"
        ],
        "correct": 0,
        "explanation": "Man-in-the-Middle атакующий перехватывает и может изменять данные между вами и сайтом."
    },
    {
        "question": "Какой из методов защиты наиболее эффективен против атак с перехватом трафика в публичных Wi-Fi сетях?",
        "options": [
            "Использование VPN",
            "Отключение Bluetooth и Wi-Fi",
            "Избегание ввода данных при подкл. к открытым сетям",
            "Все вышеперечисленное"
        ],
        "correct": 3,
        "explanation": "Все эти меры увеличивают вашу безопасность в открытых сетях."
    },
    {
        "question": "Вы скачиваете файл с популярного сайта, но перед этим видите предупреждение от браузера, что он может быть небезопасным. Какие действия следует предпринять?",
        "options": [
            "Игнорировать и скачать файл, если от известного разработчика",
            "Проверить цифровую подпись файла, сверить хеш-сумму с оригиналом",
            "Открыть файл на виртуальной машине или в песочнице",
            "Варианты b и c"
        ],
        "correct": 3,
        "explanation": "Проверка подписи и использование sandbox — безопасный подход."
    },
    {
        "question": "Какой способ защиты наиболее эффективен для предотвращения утечки данных в случае компрометации вашего пароля?",
        "options": [
            "Использование уникальных паролей для каждого сервиса",
            "Включение двухфакторной аутентификации (2FA)",
            "Регулярная проверка своих данных на утечки",
            "Все вышеперечисленные методы"
        ],
        "correct": 3,
        "explanation": "Комплексный подход — лучшая защита."
    }
]


def init_safety_test_handlers(bot_instance, progress_dict, keyboard_func) -> None:
    bot = bot_instance
    user_progress = progress_dict
    create_main_keyboard = keyboard_func

    @bot.message_handler(commands=["safety_test"])
    def start_safety_test_command(message):
        user_id = message.from_user.id
        chat_id = message.chat.id

        user_progress[user_id] = {"current_question": 0, "score": 0}

        bot.send_message(
            chat_id,
            "📋 Начинаем тест! Выберите правильный вариант, нажав на кнопку ниже:",
            reply_markup=types.ReplyKeyboardRemove()
        )
        ask_question(chat_id, user_id)

    def ask_question(chat_id: int, user_id: int) -> None:
        if user_id not in user_progress:
            bot.send_message(chat_id, "Произошла ошибка. Начните тест заново.",
                             reply_markup=create_main_keyboard())
            return

        current_q_index = user_progress[user_id]["current_question"]

        if current_q_index >= len(SAFETY_QUESTIONS):
            finalize_test(chat_id, user_id)
            return

        question_data = SAFETY_QUESTIONS[current_q_index]

        markup = types.ReplyKeyboardMarkup(one_time_keyboard=True, resize_keyboard=True)
        for option in question_data["options"]:
            markup.add(types.KeyboardButton(option))

        bot.send_message(
            chat_id,
            f"*Вопрос {current_q_index + 1} из {len(SAFETY_QUESTIONS)}*\n\n{question_data['question']}",
            reply_markup=markup,
            parse_mode="Markdown"
        )

    @bot.message_handler(func=lambda msg: is_answer(msg.text))
    def handle_text_answer(message):
        user_id = message.from_user.id
        chat_id = message.chat.id

        if user_id not in user_progress:
            bot.send_message(chat_id, "Тест не найден. Возможно, он уже завершён.",
                             reply_markup=create_main_keyboard())
            return

        current_q_index = user_progress[user_id]["current_question"]
        question_data = SAFETY_QUESTIONS[current_q_index]

        try:
            selected_index = question_data["options"].index(message.text.strip())
        except ValueError:
            bot.send_message(chat_id, "Пожалуйста, выберите ответ, используя кнопки ниже.")
            return

        correct_index = question_data["correct"]
        is_correct = selected_index == correct_index

        response = "✅ Правильно!" if is_correct else (
            f"❌ Неверно. Правильный ответ: *{question_data['options'][correct_index]}*"
        )
        explanation = question_data["explanation"]

        if is_correct:
            user_progress[user_id]["score"] += 1

        bot.send_message(
            chat_id,
            f"{response}\n\n📚 Пояснение: {explanation}",
            parse_mode="Markdown",
            reply_markup=types.ReplyKeyboardRemove()
        )

        user_progress[user_id]["current_question"] += 1
        ask_question(chat_id, user_id)

    def is_answer(text: str) -> bool:
        return any(text == option for q in SAFETY_QUESTIONS for option in q["options"])

    def finalize_test(chat_id: int, user_id: int) -> None:
        if user_id not in user_progress:
            return

        score = user_progress[user_id]["score"]
        total = len(SAFETY_QUESTIONS)
        percentage = (score / total) * 100

        if percentage == 100:
            feedback = "🎉 Отличный результат! Вы прекрасно осведомлены об основах безопасности!"
        elif percentage >= 70:
            feedback = f"👍 Хороший результат ({percentage:.0f}%)! Вы неплохо разбираетесь, но всегда есть что улучшить."
        elif percentage >= 40:
            feedback = f"⚠️ Неплохо ({percentage:.0f}%), но стоит подтянуть знания, чтобы лучше защитить себя."
        else:
            feedback = f"😥 Низкий результат ({percentage:.0f}%). Рекомендую изучить материалы по цифровой безопасности."

        recommendations = "\n".join([
            "1. Используйте уникальные и сложные пароли.",
            "2. Включайте двухфакторную аутентификацию (2FA).",
            "3. Проверяйте адреса сайтов и ссылок.",
            "4. Не скачивайте файлы из непроверенных источников.",
            "5. Используйте VPN в общественных сетях.",
            "6. Регулярно обновляйте ПО и системы.",
            "7. Изучайте фишинг и методы социальной инженерии."
        ])

        bot.send_message(
            chat_id,
            f"🏁 Тест завершён!\n\nПравильных ответов: {score} из {total}\n\n"
            f"{feedback}\n\n📌 Рекомендации:\n{recommendations}\n\n"
            "🔐 *Узнайте больше об онлайн-безопасности на сайтах Kaspersky, ESET и других.*",
            parse_mode="Markdown",
            reply_markup=create_main_keyboard()
        )

        user_progress.pop(user_id, None)