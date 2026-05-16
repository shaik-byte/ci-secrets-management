from django.contrib import admin

# Register your models here.

from .models import TrustedCIDR


@admin.register(TrustedCIDR)
class TrustedCIDRAdmin(admin.ModelAdmin):
    list_display = ("cidr_range", "description", "is_active", "created_by", "created_at", "updated_at")
    list_filter = ("is_active", "created_at", "updated_at")
    search_fields = ("cidr_range", "description", "created_by__username")
    readonly_fields = ("created_at", "updated_at")
