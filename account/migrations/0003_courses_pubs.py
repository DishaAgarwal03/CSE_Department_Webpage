# Generated by Django 5.0.3 on 2024-04-06 11:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0002_document'),
    ]

    operations = [
        migrations.CreateModel(
            name='Courses',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cname', models.CharField(max_length=255)),
                ('c_code', models.IntegerField()),
                ('cred', models.IntegerField()),
            ],
            options={
                'ordering': ['cname'],
            },
        ),
        migrations.CreateModel(
            name='Pubs',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('auth', models.CharField(max_length=1024)),
                ('pub_title', models.CharField(max_length=255)),
                ('topic', models.CharField(max_length=255)),
                ('pub_date', models.DateField()),
            ],
            options={
                'ordering': ['auth'],
            },
        ),
    ]
