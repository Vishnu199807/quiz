from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    email = models.EmailField(unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

class Quiz(models.Model):
    DIFF_CHOICES = {
        ('Easy', "Easy"),
        ('Medium', 'Medium'),
        ('Hard', 'Hard')
    }
    title = models.CharField(max_length=500)
    topic = models.CharField(max_length=100)
    difficulty_level = models.CharField(max_length=50, choices=DIFF_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    creator = models.ForeignKey(User, related_name='quizzes_created', on_delete=models.CASCADE)

    def __str__(self):
        return self.title


class Question(models.Model):
    quiz = models.ForeignKey(Quiz, related_name='questions', on_delete=models.CASCADE)
    text = models.CharField(max_length=200)

    def __str__(self):
        return self.text


class Choice(models.Model):
    question = models.ForeignKey(Question, related_name='choices', on_delete=models.CASCADE)
    text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)

    def __str__(self):
        return self.text


class QuizResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)
    score = models.IntegerField()

    def __str__(self):
        return f"{self.user.username} - {self.quiz.title}: Score {self.score}"

