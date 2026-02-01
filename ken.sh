cd /var/www/pterodactyl

# 1. Buat Folder View Security
mkdir -p resources/views/admin/security

# 2. Buat File View untuk Security Dashboard (Tema Asli)
cat > resources/views/admin/security/index.blade.php << 'EOF'
@extends('layouts.admin')

@section('title')
    Security Settings
@endsection

@section('content-header')
    <h1>Security Settings<small>Manage panel security and IP blocking.</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Security</li>
    </ol>
@stop

@section('content')
<div class="row">
    <div class="col-xs-12">
        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title">Security Control</h3>
            </div>
            <div class="box-body">
                <div class="row">
                    <div class="col-md-4">
                        <div class="info-box bg-red">
                            <span class="info-box-icon"><i class="fa fa-ban"></i></span>
                            <div class="info-box-content">
                                <span class="info-box-text">Banned IPs</span>
                                <span class="info-box-number">0</span>
                            </div>
                        </div>
                    </div>
                </div>
                <p>Fitur keamanan tambahan berhasil diaktifkan. Gunakan menu ini untuk mengontrol akses panel.</p>
            </div>
        </div>
    </div>
</div>
@stop
EOF

# 3. Tambahkan Rute ke routes/admin.php (Tanpa Menghapus yang Lama)
# Kita tambahkan di baris paling bawah sebelum penutup
cat >> routes/admin.php << 'EOF'

// Custom Security Feature
Route::group(['prefix' => 'security'], function () {
    Route::get('/', function () {
        return view('admin.security.index');
    })->name('admin.security');
});
EOF

# 4. Sisipkan Menu ke Sidebar (Otomatis)
# Kita cari menu "Settings" lalu kita taruh menu "Security" di bawahnya
sed -i '/fa-gears/!b;n;a\        <li class="{{ request()->is("admin/security*") ? "active" : "" }}">\n            <a href="{{ route("admin.security") }}">\n                <i class="fa fa-shield"></i> <span>Security Settings</span>\n            </a>\n        </li>' resources/views/layouts/admin.blade.php

# 5. Ritual Bersih-Bersih
php artisan view:clear
php artisan route:clear
chown -R www-data:www-data *
