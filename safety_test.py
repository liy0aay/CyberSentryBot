import telebot
from telebot import types

def init_safety_test_handlers(bot_instance, progress_dict, keyboard_func):
    global bot, user_progress, create_main_keyboard
    bot = bot_instance
    user_progress = progress_dict
    create_main_keyboard = keyboard_func

    SAFETY_QUESTIONS = [
    {
        "question": "Как злоумышленники могут получить ваш пароль, даже если сайт, которым вы пользуетесь, сам не подвергся взлому?",
        "options": [
            "Через утечку базы данных с другого сервиса, где вы использовали тот же пароль",
            "С помощью автоматического подбора паролей (Brute Force)",
            "Через фишинговые атаки и поддельные страницы входа",
            "Все перечисленное"
        ],
        "correct": 3,
        "explanation": "Все перечисленные методы могут быть использованы для кражи паролей."
    },
    {
        "question": "Каким способом можно подделать URL сайта, чтобы он выглядел как настоящий?",
        "options": [
            "Использовать поддельные сертификаты безопасности",
            "Создать домен с похожими символами (например, g00gle.com вместо google.com)",
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
            "Сканируя данные карты через беспроводные платежи (NFC)",
            "Все вышеуказанные методы"
        ],
        "correct": 3,
        "explanation": "Все эти методы представляют угрозу безопасности."
    },
    {
        "question": "Что из перечисленного является наименее надежным способом хранения паролей?",
        "options": [
            "Использование менеджера паролей с мастер-ключом",
            "Запись паролей в зашифрованный документ",
            "Запоминание всех паролей в голове",
            "Хранение всех паролей в текстовом файле на рабочем столе"
        ],
        "correct": 3,
        "explanation": "Хранение паролей в обычном текстовом файле — крайне ненадежно."
    },
    {
        "question": "Что делает злоумышленник при атаке типа Man-in-the-Middle?",
        "options": [
            "Прослушивает и изменяет передаваемые данные между вами и сайтом",
            "Использует ваш IP-адрес для анонимного серфинга в сети",
            "Встраивает вредоносную рекламу в веб-страницы",
            "Отправляет вам вредоносные письма с поддельных доменов"
        ],
        "correct": 0,
        "explanation": "Man-in-the-Middle атакующий перехватывает и может изменять данные между вами и сайтом."
    },
    {
        "question": "Какой из методов защиты наиболее эффективен против атак с перехватом трафика в публичных Wi-Fi сетях?",
        "options": [
            "Использование VPN",
            "Отключение Bluetooth и Wi-Fi, если они не используются",
            "Избегание ввода личных данных при подключении к открытым сетям",
            "Все вышеперечисленное"
        ],
        "correct": 3,
        "explanation": "Все эти меры увеличивают вашу безопасность в открытых сетях."
    },
    {
        "question": "Вы скачиваете файл с популярного сайта, но перед этим видите предупреждение от браузера, что он может быть небезопасным. Какие действия следует предпринять?",
        "options": [
            "Игнорировать предупреждение и скачать файл, если он от известного разработчика",
            "Проверить цифровую подпись файла и сверить хеш-сумму с оригиналом",
            "Открыть файл на виртуальной машине или в песочнице (sandbox)",
            "Варианты b и c"
        ],
        "correct": 3,
        "explanation": "Проверка подписи и использование sandbox — безопасный подход."
    },
    {
        "question": "Какой из приведенных сценариев указывает на возможную атаку социальной инженерии?",
        "options": [
            "Вы получаете звонок от «банковского сотрудника», который просит подтвердить перевод, которого вы не совершали",
            "Вам приходит письмо с вложением, якобы от вашего коллеги, но с необычным текстом",
            "Незнакомец в социальных сетях просит вас помочь ему восстановить доступ к его аккаунту",
            "Все вышеперечисленные ситуации"
        ],
        "correct": 3,
        "explanation": "Все эти примеры — типичные атаки социальной инженерии."
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
    

    @bot.message_handler(commands=['safety_test'])
    def start_safety_test_command(message):
        """Обработчик команды /safety_test"""
        user_id = message.from_user.id
        chat_id = message.chat.id
        user_progress[user_id] = {"current_question": 0, "score": 0}
        bot.send_message(chat_id, "Начинаем тест! Выберите правильный вариант ответа.", 
                       reply_markup=types.ReplyKeyboardRemove())
        ask_question(chat_id, user_id)
    
    def ask_question(chat_id: int, user_id: int):
        """Отправка вопроса с вариантами ответов"""
        if user_id not in user_progress:
            return

        current_q_index = user_progress[user_id]["current_question"]
        if current_q_index >= len(SAFETY_QUESTIONS):
            finalize_test(chat_id, user_id)
            return

        markup = types.InlineKeyboardMarkup(row_width=1)
        question_data = SAFETY_QUESTIONS[current_q_index]

        for idx, option in enumerate(question_data["options"]):
            markup.add(types.InlineKeyboardButton(
                text=option,
                callback_data=f"answer_{current_q_index}_{idx}"
            ))

        bot.send_message(
            chat_id,
            f"Вопрос {current_q_index + 1}/{len(SAFETY_QUESTIONS)}\n\n" +
            question_data["question"],
            reply_markup=markup,
            parse_mode="Markdown"
        )

    @bot.callback_query_handler(func=lambda call: call.data.startswith('answer_'))
    def handle_answer_callback(call):
        """Обработчик ответов на вопросы"""
        user_id = call.from_user.id
        chat_id = call.message.chat.id

        if user_id not in user_progress:
            bot.answer_callback_query(call.id, "Тест не найден для вас. Возможно, бот перезапускался.")
            bot.edit_message_text(
                chat_id=chat_id,
                message_id=call.message.message_id,
                text="Произошла ошибка. Пожалуйста, начните тест заново.",
                reply_markup=None
            )
            return

        try:
            _, q_idx_str, a_idx_str = call.data.split('_')
            q_idx = int(q_idx_str)
            a_idx = int(a_idx_str)
        except ValueError:
            print(f"Ошибка парсинга callback_data: {call.data}")
            bot.answer_callback_query(call.id, "Ошибка обработки ответа.")
            return

        if q_idx != user_progress[user_id]["current_question"]:
            bot.answer_callback_query(call.id, "Это ответ на предыдущий вопрос.")
            return

        question = SAFETY_QUESTIONS[q_idx]
        is_correct = (a_idx == question["correct"])

        if is_correct:
            user_progress[user_id]["score"] += 1
            result_text = "✅ Правильно!\n\n"
        else:
            result_text = f"❌ Неверно. Правильный ответ: {question['options'][question['correct']]}\n\n"

        bot.edit_message_text(
            chat_id=chat_id,
            message_id=call.message.message_id,
            text=f"Вопрос {q_idx + 1}: {question['question']}\n\n" +
                 f"Ваш ответ: {question['options'][a_idx]}\n\n" +
                 result_text +
                 f"Пояснение: {question['explanation']}",
            reply_markup=None,
            parse_mode="Markdown"
        )
        bot.answer_callback_query(call.id)

        user_progress[user_id]["current_question"] += 1
        if user_progress[user_id]["current_question"] < len(SAFETY_QUESTIONS):
            ask_question(chat_id, user_id)
        else:
            finalize_test(chat_id, user_id)

    def finalize_test(chat_id: int, user_id: int):
        """Завершение теста и вывод результатов"""
        if user_id not in user_progress: 
            return

        score = user_progress[user_id]["score"]
        total = len(SAFETY_QUESTIONS)
        percentage = (score / total) * 100 if total > 0 else 0

        feedback = ""
        if percentage == 100:
            feedback = "🎉 Отличный результат! Вы прекрасно осведомлены об основах безопасности!"
        elif percentage >= 70:
            feedback = f"👍 Хороший результат ({percentage:.0f}%)! Вы неплохо разбираетесь, но всегда есть что улучшить."
        elif percentage >= 40:
            feedback = f"⚠️ Неплохо ({percentage:.0f}%), но стоит подтянуть знания, чтобы лучше защитить себя."
        else:
            feedback = f"😥 Низкий результат ({percentage:.0f}%). Рекомендую изучить материалы по цифровой безопасности."

        recommendations_header = "\n\n📌 Ключевые правила безопасности:"
        recommendations = [
            "1. Используйте сложные и уникальные пароли для каждого сервиса.",
            "2. Включайте двухфакторную аутентификацию (2FA) везде, где возможно.",
            "3. Будьте подозрительны к неожиданным письмам, сообщениям и звонкам, особенно если просят личные данные или деньги.",
            "4. Проверяйте адреса ссылок перед переходом, особенно в подозрительных сообщениях.",
            "5. Не скачивайте файлы из ненадежных источников.",
            "6. Используйте VPN при подключении к общественным Wi-Fi сетям.",
            "7. Регулярно обновляйте ПО и операционную систему.",
            "8. Узнайте больше о фишинге и социальной инженерии."
        ]

        final_message = (
            f"🏁 Тест завершен!\n\n"
            f"Правильных ответов: {score} из {total}\n\n"
            f"{feedback}\n"
            f"{recommendations_header}\n" +
            "\n".join(recommendations) +
            "\n\n🔗 *Подробнее об онлайн-безопасности можно узнать на сайтах экспертов, например, Kaspersky или ESET.*"
        )

        bot.send_message(
            chat_id,
            final_message,
            reply_markup=create_main_keyboard(),
            parse_mode="Markdown"
        )

        if user_id in user_progress:
            del user_progress[user_id]

def ask_question(chat_id: int, user_id: int):
    """Отправка вопроса с вариантами ответов"""
    if user_id not in user_progress:
        bot.send_message(chat_id, "Произошла ошибка с тестом. Пожалуйста, начните заново.", 
                       reply_markup=create_main_keyboard())
        return

    current_q_index = user_progress[user_id]["current_question"]
    if current_q_index >= len(SAFETY_QUESTIONS):
        finalize_test(chat_id, user_id)
        return

    markup = types.InlineKeyboardMarkup(row_width=1)
    question_data = SAFETY_QUESTIONS[current_q_index]

    for idx, option in enumerate(question_data["options"]):
        markup.add(types.InlineKeyboardButton(
            text=option,
            callback_data=f"answer_{current_q_index}_{idx}"
        ))

    bot.send_message(
        chat_id,
        f"Вопрос {current_q_index + 1}/{len(SAFETY_QUESTIONS)}\n\n" +
        question_data["question"],
        reply_markup=markup,
        parse_mode="Markdown"
    )