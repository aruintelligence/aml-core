# ĀML في دقيقة واحدة

**الحالة: DRAFT — صفحة إثبات مترجمة**

<div dir="rtl">

ĀML هو جدار حماية للواجهة بين نية الذكاء الاصطناعي أو التطبيق وبين البكسلات المعروضة.

قاعدة النموذج الأولي:

```text
render_allowed = restoration_value >= attention_cost
```

جرّبه هنا:
https://aruintelligence.github.io/aml-core/playground.html

اجعل `restoration_value` أقل من `attention_cost`، ثم أعد التجميع وافحص القرار.

بعد ذلك افتح View Meaning:
https://aruintelligence.github.io/aml-core/view-meaning.html

ĀML نموذج أولي يعمل، وليس معياراً عالمياً معتمداً.

</div>
