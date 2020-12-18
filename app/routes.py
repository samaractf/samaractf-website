import hashlib
import json
import os
import time

from sqlalchemy import and_
import flask_admin as admin
from flask import render_template, request, flash, redirect, url_for, send_from_directory, make_response, abort
from flask_admin import Admin, expose, base
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user, login_user, logout_user
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename

from app import app
from app import db
from app.decorators import admin_required, write_required, samara_required
from app.email import send_password_reset_email
from app.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm, UploadForm, ChoiceForm
from app.models import User, Role, Page, Tag, PostsTags, Permission, Task, UsersTasks, Order, UsersOrder


class MyAdmin(admin.AdminIndexView):
    @expose('/')
    @admin_required
    def index(self):
        print(current_user.get_id())
        return super(MyAdmin, self).index()

    @expose('/test')
    @admin_required
    def test(self):
        return 'Hello '


    @expose('/shop', methods=['GET'])
    @samara_required
    def shop(self):
        orders = Order.query.all()
        return render_template('shop.html', orders=orders)


    @expose('/buy/<int:id>', methods=['GET'])
    @samara_required
    def buy(self,id):
        target_order = Order.query.filter(Order.id == id).first()
        user = current_user.load_current_user()
        if target_order.count >= 1:
            if current_user not in target_order.users:
                if user[0].buy(target_order.cost):  # buy order logic
                    target_order.count -= 1
                    db.session.add(user[0])
                    target_order.users.extend(user)
                    db.session.add(target_order)
                    secret = target_order.secret
                    db.session.commit()
                    return secret
                return abort(403)
            else:
                return target_order.secret
        return abort(403)

    @write_required
    @expose('/uploads_img', methods=['GET', 'POST'])
    def uploaded_file(self):
        print('i call!')
        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            filename = secure_filename(file.filename)
            path = app.config['UPLOAD_PHOTOS_RELATIVE'] + '/' + filename
            if file and allowed_file(filename):
                file.save(os.path.join(app.config['UPLOAD_PHOTOS_FOLDER'], filename))
                print(json.dumps({'link': path}))
                return json.dumps({'link': path})
            # return send_from_directory(app.config['UPLOADED_PHOTOS_FOLDER'], filename)


def download_img(form):
    filename = secure_filename(form.data['file'].filename)
    formats = '.' + filename.split('.')[-1]
    name = hashlib.md5(filename.encode() + str(time.time()).encode()).hexdigest()[:20] + formats
    form.data['file'].save(os.path.join(app.config['UPLOAD_PHOTOS_FOLDER'], name))
    return name


class TestAdmin(ModelView):
    default_view = 'Публикация'

    @write_required
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        form = UploadForm()

        form2 = ChoiceForm(request.form)

        datas = ChoiceForm(request.form)
        datas.multi_select.query = Tag.query.order_by('name').paginate()
        #           print(str(form2.multi_select))
        # print(str(form2.multi_select.query))
        # print(form2.multi_select.query.items)
        print(form.data)

        if form.validate_on_submit():
            name = download_img(form)

            # photos.save(filename, name=name + '.')
            success = True
        else:
            success = False
        if request.method == "GET":
            return self.render("admin/create.html", form=form, form2=form2, datas=datas, success=success)  # updated
        elif request.method == "POST":
            print(request.form)
            t = Tag.query.filter(Tag.id.in_(form2.data['multi_select'].split(','))).all()
            new_post = Page(
                t,
                request.form['title'],
                name,
                request.form['content'],
                current_user.get_id(),
                True
            )
            db.session.add(new_post)
            db.session.commit()
            return render_template("index.html")

    @write_required
    @expose('/edit/<int:id>', methods=['GET', 'POST'])
    def edit_post(self, id):
        form = UploadForm()
        flag = True
        success = False
        if flag:
            if form.validate_on_submit():
                name = download_img(form)
                # redirect(url_for('admin.uploaded_file'), code=307)

        page = db.session.query(Page).filter_by(id=id).first_or_404()
        if request.method == "GET":
            return self.render('admin/edit.html', page=page, form=form, flag=flag,
                               rules=permission_check(Permission.WRITE))  # updated
        elif request.method == "POST":
            page.body = request.form['new_content']
            page.title = request.form['new_title']
            if request.form.get('visible'):
                page.is_visible = True
            else:
                page.is_visible = False
            if request.form.get('change_img'):
                page.imagename = name

            db.session.commit()
            return self.render('admin/edit.html', page=page, form=form, rules=permission_check(Permission.WRITE))


admin = Admin(app, name='samaraCTF', template_mode='bootstrap3', index_view=MyAdmin())


class SecurityView(ModelView):
    @admin_required
    def is_accessible(self):
        return True


"""
ModelView - не использовать без обертки SecutiryView!
"""
admin.add_view(SecurityView(User, db.session))
admin.add_view(SecurityView(Role, db.session))
admin.add_view(SecurityView(Tag, db.session))
admin.add_view(SecurityView(PostsTags, db.session))
admin.add_view(SecurityView(Task, db.session))
admin.add_view(SecurityView(UsersTasks, db.session))
# admin.add_view(SecurityView(Page, db.session))
admin.add_view(TestAdmin(Page, db.session))
admin.add_view(SecurityView(Order, db.session))
admin.add_view(SecurityView(UsersOrder, db.session))
admin.add_link(base.MenuLink(name='Home Page', url='/', category='urls'))


@app.after_request
def add_header(response):
    #response = make_response()
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        else:
            # Keep the user info in the session using Flask-Login
            login_user(user, remember=form.remember_me.data)

        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


def permission_check(permission):
    flag = False
    try:
        if current_user.can(permission):
            return True
        else:
            return False
    except AttributeError:
        return False
    return flag


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    """

    TODO
    отправляется много запросов к бд. Уместить всё в 1-2
    """
    # получаем уникальные категории из тасков
    if current_user.is_authenticated:
        if request.method == 'GET':
            category_tasks = sorted(list(set([r.category for r in Task.query.order_by(Task.category)])))
            # создаем словарь, типа {категория(уник):(список записей, из этой категории)}
            category_class = {a: Task.query.filter(Task.category == a).all() for a in category_tasks}

            user = current_user.load_current_user()[0]
            resolved_tasks = user.tasks

            return render_template('tasks.html', category_tasks=category_class, resolved_tasks=resolved_tasks)
        if request.method == 'POST':
            target_id = request.form['id']
            target_flag = request.form['flag'].strip()

            target_task = Task.query.filter(Task.id == target_id).first()
            user = current_user.load_current_user() #get user
            #print(user[0].tasks)

            if target_task in user[0].tasks: #find in resolved tasksk
                dont_resolve = False
            else:
                dont_resolve = True
            if dont_resolve:
                if target_task.flag == target_flag:
                    user[0].get_money(target_task.price)
                    target_task.users.extend(user)
                    db.session.add(target_task)
                    #db.session.add(user[0])
                    db.session.commit()
                    return redirect(url_for('tasks'))
                else:
                    return redirect(url_for('tasks'))
            else:
                return redirect(url_for('tasks'))
    else:
        return abort(403)


@app.route('/articles')
def articles():
    page = request.args.get('page', 1, type=int)
    tag = request.args.get('tag', type=str)
    # posts = db.session.query(Page).all()
    if not permission_check(Permission.WRITE):
        if tag != None:
            pagination = Page.query.filter(and_(Page.is_visible == True,Page.tags.any(name=tag))).order_by(
                Page.timestamp.desc()).paginate(page,
                                                per_page=
                                                app.config[
                                                    'FLASKY_POSTS_PER_PAGE'],
                                                error_out=False)
        else:
            pagination = Page.query.filter(Page.is_visible == True).order_by(Page.timestamp.desc()).paginate(page,
                                                                                                             per_page=
                                                                                                             app.config[
                                                                                                                 'FLASKY_POSTS_PER_PAGE'],
                                                                                                             error_out=False)
    else:
        if tag != None:
            pagination = Page.query.filter(Page.tags.any(name=tag)).order_by(Page.timestamp.desc()).paginate(page,
                                                                                                             per_page=
                                                                                                             app.config[
                                                                                                                 'FLASKY_POSTS_PER_PAGE'], \
                                                                                                             error_out=False)
        else:
            pagination = Page.query.order_by(Page.timestamp.desc()).paginate(page, per_page=app.config[
                'FLASKY_POSTS_PER_PAGE'], \
                                                                             error_out=False)
    posts = pagination.items
    return render_template('articles.html', posts=posts, rules=permission_check(Permission.ADMIN),
                           pagination=pagination)


@app.route('/scoreboard')
def scoreboard():
    category_tasks = set([r.category for r in Task.query.order_by(Task.category)]) #true all category
    data_template = dict.fromkeys(category_tasks,0)#{'category':0}
    users = db.session.query(User).all()
    resolved_tasks_from_manytomany = reversed(db.session.query(UsersTasks).all())
    users_data = []
    for user in users:
        all_score = 0
        data_temp = data_template.copy()
        resolved_tasks_from_users = user.load_current_user()[0].tasks
        for task in resolved_tasks_from_users:
            data_temp[task.category] += task.price
            all_score += task.price
        data_temp['username'] = user.username
        data_temp['all_score'] = all_score
        users_data.append(data_temp)
    users_data.sort(key=lambda i:i['all_score'], reverse=True)
    return render_template('scoreboard.html', categories=category_tasks, data=users_data, resolved_tasks=resolved_tasks_from_manytomany)

@app.route('/articles/<int:id>', methods=['GET'])
def post(id):
    page = db.session.query(Page).filter_by(id=id).first_or_404()
    if page.is_visible == False and not permission_check(Permission.WRITE):
        abort(404)
    return render_template('post.html', page=page)


@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')


"""
https://t.me/joinchat/KzSyxkkbI2u9MZ1vncBBPA
"""


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_PHOTOS_FOLDER'], filename)


# @app.route('/load_files', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',
                                    filename=filename))
